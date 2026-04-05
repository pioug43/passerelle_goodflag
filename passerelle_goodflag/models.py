"""
Modèle principal du connecteur Goodflag pour Passerelle.

GoodflagResource : connecteur Passerelle (hérite de BaseResource)
GoodflagWorkflowTrace : corrélation workflow Goodflag / demande Publik
GoodflagWebhookEvent : journalisation des webhooks reçus
GoodflagDocumentTrace : métadonnées des documents uploadés / signés
"""

import base64
import hmac
import io
import ipaddress
import json
import logging
import time
import zipfile
from urllib.parse import urlparse

from django.core.cache import cache
from django.db import models
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from passerelle.base.models import BaseResource
from passerelle.utils.api import endpoint

from .client import GoodflagClient, _sanitize_for_log
from .exceptions import (
    GoodflagError,
    GoodflagRateLimitError,
    GoodflagValidationError,
)

logger = logging.getLogger(__name__)

# Statuts finaux d'un workflow Goodflag (utilisés dans hourly, sync_status, webhook)
_FINAL_STATUSES = frozenset({'finished', 'refused'})

# Taille max d'un fichier encodé en base64 (~50 Mo décodé)
_MAX_B64_LEN = int(50 * 1024 * 1024 * 4 / 3) + 1024

# Clés PII à masquer dans les logs debug
_PII_KEYS = frozenset({
    'recipient_email', 'recipient_phone', 'recipient_firstname',
    'recipient_lastname', 'email', 'firstName', 'lastName',
    'phoneNumber', 'phone', 'file', 'file_base64', 'file_url',
    'content',
})


def _sniff_content_type(content, declared_type):
    """
    Détecte le type MIME réel d'un fichier par ses magic bytes.

    WCS renvoie souvent Content-Type: text/html ou application/octet-stream
    même pour des PDFs valides. On se base sur le contenu réel.
    """
    if content[:4] == b'%PDF':
        return 'application/pdf'
    if content[:4] == b'PK\x03\x04':
        return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    if content[:3] in (b'\xff\xd8\xff',):
        return 'image/jpeg'
    if content[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    # Aucun magic byte reconnu : garder le type déclaré
    return declared_type


def _validate_file_url(url):
    """
    Valide qu'une URL de fichier ne pointe pas vers une ressource interne
    (protection contre les attaques SSRF).

    Rejette :
    - Schémas non-HTTP (file://, ftp://, gopher://, etc.)
    - Adresses IP privées / loopback / link-local / réservées
    - Hostname résolu vers une adresse privée (non vérifié ici — résolution DNS
      hors scope, mais le schéma et la forme littérale sont contrôlés)

    Lève GoodflagValidationError si l'URL est suspecte.
    """
    if not url:
        raise GoodflagValidationError("file_url is required")
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise GoodflagValidationError(
            f"file_url scheme '{parsed.scheme}' not allowed (http/https only)"
        )
    hostname = parsed.hostname or ''
    # Rejeter les IP littérales privées / réservées
    try:
        addr = ipaddress.ip_address(hostname)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            raise GoodflagValidationError(
                f"file_url points to a non-routable address: {hostname}"
            )
    except ValueError:
        # Nom de domaine — on accepte, la résolution DNS n'est pas contrôlée ici
        pass
    # Rejeter les hostnames clairement locaux
    local_patterns = ('localhost', '127.', '0.0.0.0', '::1', 'metadata.google',
                      '169.254.', 'metadata.internal')
    for pat in local_patterns:
        if hostname.lower().startswith(pat) or hostname.lower() == pat.rstrip('.'):
            raise GoodflagValidationError(
                f"file_url points to a local/internal address: {hostname}"
            )


def _validate_file_content(content, content_type):
    """
    Valide le contenu d'un fichier avant upload vers Goodflag.

    Vérifie :
    - PDF : signature magique, absence de chiffrement, non vide
    - DOCX : signature ZIP (PK\\x03\\x04), fichier word/_rels/document.xml.rels présent
    - Taille non nulle

    Lève GoodflagValidationError si le fichier est invalide.
    """
    if not content:
        raise GoodflagValidationError("Le fichier est vide")

    # Détection du type réel par magic bytes, indépendamment du content_type déclaré.
    # WCS peut servir un PDF avec Content-Type: application/octet-stream.
    is_pdf_by_content = content.startswith(b'%PDF')
    is_pdf_by_type = 'pdf' in content_type.lower()

    if is_pdf_by_content or is_pdf_by_type:
        # Si le type déclaré dit PDF mais que les bytes ne correspondent pas,
        # c'est une erreur réelle (ex: HTML de login renvoyé à la place du fichier).
        if is_pdf_by_type and not is_pdf_by_content:
            raise GoodflagValidationError(
                "Le fichier n'est pas un PDF valide (signature %PDF manquante). "
                "Vérifiez que l'URL du document est accessible et retourne bien un PDF."
            )
        # Détection PDF chiffré : cherche /Encrypt dans les 2048 premiers octets
        # ou dans les 512 derniers (où se trouve souvent le trailer)
        probe = content[:2048] + content[-512:]
        if b'/Encrypt' in probe:
            raise GoodflagValidationError(
                "Le PDF est protégé par chiffrement. "
                "Goodflag ne peut pas signer un PDF chiffré. "
                "Déchiffrez le document avant de l'uploader."
            )

    elif 'wordprocessingml' in content_type or 'docx' in content_type.lower():
        # Vérification signature ZIP (DOCX = ZIP)
        if not content.startswith(b'PK\x03\x04'):
            raise GoodflagValidationError(
                "Le fichier DOCX n'est pas valide (signature ZIP manquante)"
            )
        # Vérification structure interne DOCX minimale
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = zf.namelist()
                if 'word/document.xml' not in names:
                    raise GoodflagValidationError(
                        "Le fichier DOCX est corrompu (word/document.xml manquant)"
                    )
        except zipfile.BadZipFile:
            raise GoodflagValidationError(
                "Le fichier DOCX est corrompu (archive ZIP invalide)"
            )


class GoodflagResource(BaseResource):
    """
    Connecteur Passerelle pour la signature électronique Goodflag.

    Permet à Publik (W.C.S.) de piloter un circuit de signature Goodflag :
    création de workflow, upload de documents, démarrage, suivi, récupération
    des documents signés.
    """

    # -- Champs de configuration ------------------------------------------

    base_url = models.URLField(
        _('URL de base de l\'API Goodflag'),
        max_length=512,
        help_text=_(
            'URL de base de l\'API Goodflag Workflow Manager, '
            'ex: https://sgs-demo-test01.sunnystamp.com/api'
        ),
    )

    access_token = models.CharField(
        _('Token d\'accès API'),
        max_length=512,
        help_text=_(
            'Bearer token pour l\'authentification API Goodflag '
            '(format: act_xxx.yyy)'
        ),
    )

    user_id = models.CharField(
        _('Identifiant utilisateur API'),
        max_length=256,
        help_text=_(
            'Identifiant de l\'utilisateur Goodflag propriétaire des '
            'workflows créés (format: usr_xxx). Requis pour la création '
            'de workflows.'
        ),
    )

    timeout = models.PositiveIntegerField(
        _('Timeout HTTP (secondes)'),
        default=30,
        help_text=_('Timeout en secondes pour les appels API Goodflag'),
    )

    verify_ssl = models.BooleanField(
        _('Vérifier le certificat SSL'),
        default=True,
        help_text=_(
            'Activer la vérification SSL. Ne désactiver qu\'en environnement '
            'de test explicitement.'
        ),
    )

    default_consent_page_id = models.CharField(
        _('ID de page de consentement par défaut'),
        max_length=256,
        blank=True,
        default='',
        help_text=_(
            'Identifiant de la page de consentement Goodflag par défaut '
            '(format: cop_xxx). Utilisé pour les destinataires qui n\'en '
            'spécifient pas.'
        ),
    )

    default_signature_profile_id = models.CharField(
        _('ID de profil de signature par défaut'),
        max_length=256,
        blank=True,
        default='',
        help_text=_(
            'Identifiant du profil de signature Goodflag par défaut '
            '(format: sip_xxx). Utilisé pour les documents à signer.'
        ),
    )

    default_layout_id = models.CharField(
        _('ID de layout par défaut'),
        max_length=256,
        blank=True,
        default='',
        help_text=_(
            'Identifiant du layout Goodflag par défaut (format: lay_xxx). '
            'Requis si vous utilisez des métadonnées.'
        ),
    )

    webhook_secret = models.CharField(
        _('Secret du webhook'),
        max_length=256,
        blank=True,
        default='',
        help_text=_(
            'Secret partagé pour valider les webhooks Goodflag. '
            'Note : Goodflag ne signe pas ses webhooks par HMAC. '
            'Ce champ est utilisé comme token dans l\'URL du webhook '
            'ou comme header personnalisé pour la validation.'
        ),
    )

    tenant_id = models.CharField(
        _('Identifiant du tenant'),
        max_length=256,
        blank=True,
        default='',
        help_text=_(
            'Identifiant du tenant Goodflag (format: ten_xxx). '
            'Utilisé pour les webhooks globaux.'
        ),
    )

    debug_mode = models.BooleanField(
        _('Mode debug métier'),
        default=False,
        help_text=_('Active la journalisation détaillée des appels API'),
    )

    sandbox_mode = models.BooleanField(
        _('Mode sandbox'),
        default=False,
        help_text=_('Indique que le connecteur pointe vers un environnement de test'),
    )

    retention_days = models.PositiveIntegerField(
        _('Rétention des traces (jours)'),
        default=90,
        help_text=_(
            'Durée de conservation des traces de workflows, événements webhook '
            'et documents avant purge automatique (tâche daily). Défaut : 90 jours.'
        ),
    )

    publik_callback_url = models.URLField(
        _('URL de callback Publik'),
        max_length=512,
        blank=True,
        default='',
        help_text=_(
            'URL de callback Publik/WCS à notifier lors d\'un événement webhook '
            'Goodflag (workflowFinished, workflowStopped). Laisser vide pour '
            'désactiver. Format: https://wcs.example.com/api/wf/... '
        ),
    )

    status_cache_ttl = models.PositiveIntegerField(
        _('Durée du cache statut (secondes)'),
        default=120,
        help_text=_(
            'Durée en secondes pendant laquelle le statut d\'un workflow est mis '
            'en cache pour éviter des appels API répétitifs. 0 = désactivé. '
            'Défaut : 120 secondes (2 minutes).'
        ),
    )

    # -- Méta Passerelle --------------------------------------------------

    category = _('Connecteurs métiers')

    class Meta:
        verbose_name = _('Connecteur Goodflag (signature électronique)')
        verbose_name_plural = _('Connecteurs Goodflag (signature électronique)')

    # -- Helpers -----------------------------------------------------------

    # Paramètres d'authentification Passerelle injectés dans l'URL par W.C.S.
    # — à exclure lors de la lecture des query params de données.
    _PASSERELLE_AUTH_PARAMS = frozenset({'orig', 'algo', 'timestamp', 'nonce', 'signature'})

    def _parse_payload(self, request, **kwargs):
        """
        Combine toutes les sources de données en un seul dict.

        Sources (par priorité décroissante) :
        1. kwargs passés par Passerelle (paramètres extraits de l'URL)
        2. JSON body (si content-type JSON ou body parseable)
        3. Form-encoded body (request.POST)
        4. Query string (request.GET) — hors params d'auth Passerelle
        """
        content_type = request.content_type or ''
        body = request.body

        payload = {}

        # 1. Lire la Query String (toujours utile)
        data_params = {
            k: v
            for k, v in request.GET.lists()
            if k not in self._PASSERELLE_AUTH_PARAMS
        }
        for k, v in data_params.items():
            payload[k] = v[0] if len(v) == 1 else v

        # 2. Lire le body (JSON ou Form-encoded)
        # Les params d'auth Passerelle (orig, algo, timestamp, nonce, signature)
        # peuvent être injectés dans le body par certains modes d'auth WCS —
        # on les exclut comme on le fait pour la query string.
        if 'application/json' in content_type:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({
                        k: v for k, v in body_data.items()
                        if k not in self._PASSERELLE_AUTH_PARAMS
                    })
            except (ValueError, TypeError):
                # On ignore si c'est pas du JSON valide mais qu'on a déjà des params
                if not payload:
                    raise GoodflagValidationError("Invalid JSON body")
        elif request.POST:
            for k, v in request.POST.lists():
                if k not in self._PASSERELLE_AUTH_PARAMS:
                    payload[k] = v[0] if len(v) == 1 else v
        elif body:
            # Fallback JSON si body non vide
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({
                        k: v for k, v in body_data.items()
                        if k not in self._PASSERELLE_AUTH_PARAMS
                    })
            except (ValueError, TypeError):
                pass

        # 3. Fusionner les kwargs de Passerelle (paramètres nommés dans l'URL)
        if kwargs:
            payload.update({k: v for k, v in kwargs.items() if v is not None})

        if self.debug_mode:
            safe_payload = {
                k: '***' if k in _PII_KEYS else v
                for k, v in payload.items()
            }
            logger.info("[GOODFLAG DEBUG] final payload: %r", safe_payload)

        return payload

    @staticmethod
    def _get_param(payload, key, default=None):
        """Récupère un paramètre depuis un dict JSON ou form-encoded (liste)."""
        val = payload.get(key, default)
        if isinstance(val, list):
            val = val[0] if val else default
        if val == '' and default is not None:
            return default
        return val

    def _get_client(self):
        """Retourne une instance du client Goodflag configurée."""
        return GoodflagClient(
            base_url=self.base_url,
            access_token=self.access_token,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )

    def _log_debug(self, message, *args):
        """Journalise en debug si le mode debug est activé."""
        if self.debug_mode:
            logger.info("[GOODFLAG DEBUG] " + message, *args)

    def _resolve_workflow_id(self, payload):
        """
        Résout le workflow_id depuis le payload.

        Cherche d'abord workflow_id directement, puis utilise external_ref
        comme fallback pour retrouver le workflow depuis la trace locale.
        Cela permet de récupérer le workflow_id même si la variable WCS
        goodflag_create_data_workflow_id n'a pas été correctement propagée.
        """
        workflow_id = self._get_param(payload, 'workflow_id')
        if not workflow_id:
            # Recherche de la référence externe dans plusieurs champs possibles (Publik)
            external_ref = (
                self._get_param(payload, 'external_ref')
                or self._get_param(payload, 'display_id')  # ex: "12-1"
                or self._get_param(payload, 'uuid')        # ex: "a02ca561-..."
                # Note: 'id' retiré — trop générique, risque de collision
            )
            if external_ref:
                trace = GoodflagWorkflowTrace.objects.filter(
                    resource=self,
                    external_ref=external_ref,
                ).order_by('-created_at').first()
                if trace:
                    workflow_id = trace.goodflag_workflow_id
                    logger.info(
                        "Resolved workflow_id=%s from external_ref=%s",
                        workflow_id, external_ref,
                    )
        return workflow_id

    def _build_steps(self, recipients, steps_config=None):
        """
        Construit la structure steps[] pour l'API Goodflag.

        Si steps_config est fourni, il est utilisé tel quel (format natif
        Goodflag). Sinon, on construit une étape de signature unique
        à partir de la liste de recipients.

        Chaque destinataire doit avoir au minimum un consentPageId et un
        email. Si consentPageId manque, la valeur par défaut du connecteur
        est utilisée.
        """
        if steps_config:
            # Format natif : on s'assure juste que consentPageId est présent
            for step in steps_config:
                for recipient in step.get('recipients', []):
                    if not recipient.get('consentPageId') and self.default_consent_page_id:
                        recipient['consentPageId'] = self.default_consent_page_id
            return steps_config

        # Construction simplifiée : une seule étape de type signature
        built_recipients = []
        for r in recipients:
            recipient = dict(r)
            if not recipient.get('consentPageId') and self.default_consent_page_id:
                recipient['consentPageId'] = self.default_consent_page_id
            # On supprime si c'est vide pour éviter erreur 400
            if 'consentPageId' in recipient and not recipient['consentPageId']:
                del recipient['consentPageId']
            
            # Mapping phone (Publik) -> phoneNumber (Goodflag)
            phone = recipient.pop('phone', None)
            if phone:
                recipient['phoneNumber'] = phone
            
            built_recipients.append(recipient)

        steps = [{
            'stepType': 'signature',
            'recipients': built_recipients,
            'maxInvites': 5,
        }]

        if self.debug_mode:
            logger.info("[GOODFLAG DEBUG] built steps: %r", steps)

        return steps

    def _parse_multi_recipients(self, payload):
        """
        Parse les destinataires au format form-encoded numéroté de W.C.S.

        Supporte deux formats :
        - Format indexé : recipients_0_email, recipients_0_firstname, ...,
                          recipients_1_email, recipients_1_firstname, ...
        - Format JSON  : recipients = [{"email": ..., "firstName": ...}, ...]

        Retourne une liste de dicts recipients ou None si aucun trouvé.
        """
        # Format JSON (liste dans le payload)
        recipients_raw = payload.get('recipients')
        if recipients_raw and isinstance(recipients_raw, list):
            return recipients_raw

        # Format indexé (form-encoded W.C.S.)
        _MAX_RECIPIENTS = 100
        recipients = []
        i = 0
        while i < _MAX_RECIPIENTS:
            email = self._get_param(payload, f'recipients_{i}_email')
            if not email:
                break
            recipient = {
                'email': email,
                'firstName': self._get_param(payload, f'recipients_{i}_firstname', ''),
                'lastName': self._get_param(payload, f'recipients_{i}_lastname', ''),
                'phone': self._get_param(payload, f'recipients_{i}_phone', ''),
            }
            consent_page = self._get_param(payload, f'recipients_{i}_consent_page_id')
            if consent_page:
                recipient['consentPageId'] = consent_page
            sig_profile = self._get_param(payload, f'recipients_{i}_signature_profile_id')
            if sig_profile:
                recipient['signatureProfileId'] = sig_profile
            recipients.append(recipient)
            i += 1

        return recipients if recipients else None

    # -- Parsing de fichier ------------------------------------------------

    def _parse_file_from_payload(self, payload, request):
        """
        Extrait le contenu d'un fichier depuis le payload ou la requête.

        Priorité :
          1. ``file`` (dict JSON) : {"filename": "...", "content_type": "...", "content": "<base64>"}
          2. ``request.FILES['file']`` — upload multipart Django
          3. ``file_base64`` — chaîne base64 directe
          4. ``file_url`` — URL téléchargée via la session Passerelle signée
          5. ``fields`` — objet de formulaire WCS complet (premier champ avec 'content')

        Retourne (file_content: bytes, filename: str, content_type: str).
        Lève GoodflagValidationError si aucune source n'est trouvable.
        """
        file_obj = payload.get('file')
        if isinstance(file_obj, str) and file_obj.startswith('{'):
            try:
                file_obj = json.loads(file_obj)
            except (ValueError, TypeError):
                pass

        filename = self._get_param(payload, 'filename')
        content_type = self._get_param(payload, 'content_type', 'application/pdf')
        file_content = None
        file_url = None

        if isinstance(file_obj, dict):
            file_b64 = file_obj.get('content')
            if not file_b64:
                raise GoodflagValidationError("'content' is missing in 'file' object")
            if len(file_b64) > _MAX_B64_LEN:
                raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
            file_content = base64.b64decode(file_b64)
            filename = filename or file_obj.get('filename')
            content_type = file_obj.get('content_type') or content_type
        elif request.FILES.get('file'):
            f = request.FILES['file']
            file_content = f.read()
            filename = filename or f.name
        elif self._get_param(payload, 'file_base64'):
            file_b64 = self._get_param(payload, 'file_base64')
            if len(file_b64) > _MAX_B64_LEN:
                raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
            file_content = base64.b64decode(file_b64)
        elif self._get_param(payload, 'file_url'):
            file_url = self._get_param(payload, 'file_url')
            _validate_file_url(file_url)
            resp = self.requests.get(file_url)
            if resp.status_code != 200:
                raise GoodflagError(
                    f"Failed to fetch file from URL: HTTP {resp.status_code}"
                )
            file_content = resp.content
            # Détection du type par magic bytes — prioritaire sur le Content-Type
            # déclaré par WCS qui peut être text/html, application/octet-stream, etc.
            # même pour un PDF valide.
            content_type = _sniff_content_type(file_content, content_type)
        elif isinstance(payload.get('fields'), dict):
            for field_val in payload['fields'].values():
                if isinstance(field_val, dict) and 'content' in field_val:
                    file_content = base64.b64decode(field_val['content'])
                    filename = filename or field_val.get('filename')
                    content_type = field_val.get('content_type') or content_type
                    break

        if not file_content:
            raise GoodflagValidationError(
                "'file' object, 'file_base64', 'file_url' or valid 'fields' is required"
            )

        _validate_file_content(file_content, content_type)

        if not filename and file_url:
            from urllib.parse import urlparse, unquote
            path = urlparse(file_url).path
            filename = unquote(path.rstrip('/').rsplit('/', 1)[-1]) or ''
        filename = filename or 'document.pdf'

        return file_content, filename, content_type

    # -- Notification WCS --------------------------------------------------

    _NOTIFY_EVENT_TYPES = frozenset({
        'workflowFinished', 'workflowStopped', 'workflowStarted',
        'recipientFinished', 'recipientRefused',
    })

    def _notify_wcs(self, workflow_id, event_type, normalized_status, event_id=''):
        """
        Notifie WCS d'un changement de statut via le publik_callback_url global.

        Utilise self.requests (session Passerelle avec signature d'URL) pour
        que WCS accepte l'appel.
        """
        callback_url = self.publik_callback_url
        if not callback_url:
            return

        payload = {
            'event_type': event_type,
            'workflow_id': workflow_id,
            'status': normalized_status,
            'event_id': event_id,
        }

        try:
            cb_response = self.requests.post(
                callback_url,
                json=payload,
                timeout=10,
            )
            if cb_response.status_code >= 400:
                logger.warning(
                    "WCS callback failed: HTTP %s for workflow %s (url=%s)",
                    cb_response.status_code, workflow_id, callback_url,
                )
            else:
                logger.info(
                    "WCS callback OK: workflow=%s, status=%s, HTTP %s",
                    workflow_id, normalized_status, cb_response.status_code,
                )
        except Exception as exc:
            logger.warning(
                "WCS callback exception for workflow %s: %s (url=%s)",
                workflow_id, exc, callback_url,
            )

    # -- Disponibilité et tâches planifiées --------------------------------

    def check_status(self):
        """Vérifie la disponibilité de l'API Goodflag (toutes les 5 min)."""
        client = self._get_client()
        result = client.test_connection()
        if result.get('status') != 'ok':
            raise GoodflagError(result.get('message', 'Goodflag API unreachable'))

    def hourly(self):
        """Synchronise les statuts des workflows actifs (draft/started)."""
        active_traces = GoodflagWorkflowTrace.objects.filter(
            resource=self,
            status__in=['draft', 'started'],
        )
        if not active_traces.exists():
            return

        client = self._get_client()
        for trace in active_traces:
            try:
                result = client.get_workflow(trace.goodflag_workflow_id)
                new_status = result.get('normalized_status')
                if new_status and new_status != trace.status:
                    logger.info(
                        "Hourly sync: workflow %s status %s -> %s",
                        trace.goodflag_workflow_id, trace.status, new_status,
                    )
                    old_status = trace.status
                    trace.status = new_status
                    trace.save(update_fields=['status', 'updated_at'])

                    # Notifier WCS si transition vers un état final
                    if new_status in _FINAL_STATUSES and old_status not in _FINAL_STATUSES:
                        event_type = (
                            'workflowFinished' if new_status == 'finished'
                            else 'workflowStopped'
                        )
                        self._notify_wcs(
                            trace.goodflag_workflow_id, event_type, new_status,
                        )
            except GoodflagRateLimitError as exc:
                wait = getattr(exc, 'retry_after', 60) or 60
                logger.warning(
                    "Hourly sync: rate limit hit for workflow %s, "
                    "stopping sync for this run (retry_after=%ds)",
                    trace.goodflag_workflow_id, wait,
                )
                # Interrompre la boucle immédiatement : dormir bloquerait
                # le worker Passerelle pour tous les autres connecteurs.
                break
            except GoodflagError as exc:
                logger.warning(
                    "Hourly sync failed for workflow %s: %s",
                    trace.goodflag_workflow_id, exc,
                )

    def daily(self):
        """Purge les anciennes traces (selon retention_days, défaut 90 jours)."""
        from datetime import timedelta
        limit = timezone.now() - timedelta(days=self.retention_days)

        wf_deleted, _ = GoodflagWorkflowTrace.objects.filter(
            resource=self,
            created_at__lt=limit,
        ).delete()

        wbe_deleted, _ = GoodflagWebhookEvent.objects.filter(
            resource=self,
            received_at__lt=limit,
        ).delete()

        doc_deleted, _ = GoodflagDocumentTrace.objects.filter(
            resource=self,
            uploaded_at__lt=limit,
        ).delete()

        if wf_deleted or wbe_deleted or doc_deleted:
            logger.info(
                "Daily purge: %d workflows, %d events, %d docs removed",
                wf_deleted, wbe_deleted, doc_deleted,
            )

    # -- Endpoints --------------------------------------------------------


    @endpoint(
        name='create-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Crée un workflow de signature Goodflag (statut draft, sans document)'),
        long_description=_(
            'Crée un nouveau workflow Goodflag avec les signataires et métadonnées. '
            'Le workflow est créé en statut "draft" : aucun document n\'est uploadé, '
            'aucune invitation n\'est envoyée. Enchaîner avec upload-document puis '
            'start-workflow, ou utiliser submit-workflow pour tout faire en un appel.\n\n'
            'Format 1 — signataire unique (paramètres plats, form W.C.S.) :\n'
            '{\n'
            '  "name": "Signature convention {{ form_number }}",\n'
            '  "recipient_email": "{{ form_var_email_signataire }}",\n'
            '  "recipient_firstname": "{{ form_var_prenom_signataire }}",\n'
            '  "recipient_lastname": "{{ form_var_nom_signataire }}",\n'
            '  "recipient_phone": "{{ form_var_telephone_portable }}",\n'
            '  "external_ref": "{{ form_number }}"\n'
            '}\n\n'
            'Format 2 — multi-signataires (liste JSON) :\n'
            '{\n'
            '  "name": "Convention multi-sig",\n'
            '  "recipients": [\n'
            '    {"email": "sig1@ex.com", "firstName": "Alice", "lastName": "Martin"},\n'
            '    {"email": "sig2@ex.com", "firstName": "Bob", "lastName": "Dupont"}\n'
            '  ],\n'
            '  "external_ref": "{{ form_number }}"\n'
            '}\n\n'
            'Format 3 — steps natifs Goodflag (approbation + signature) :\n'
            '{\n'
            '  "name": "Approbation + Signature",\n'
            '  "steps": [\n'
            '    {"stepType": "approval", "recipients": [{"email": "resp@ex.com", '
            '"firstName": "Chef", "lastName": "Service", "consentPageId": "cop_xxx"}]},\n'
            '    {"stepType": "signature", "recipients": [{"email": "sig@ex.com", '
            '"firstName": "Jean", "lastName": "Dupont", "consentPageId": "cop_yyy"}]}\n'
            '  ],\n'
            '  "external_ref": "{{ form_number }}"\n'
            '}\n\n'
            'Format 4 — multi-signataires indexé (form W.C.S. avec champs dynamiques) :\n'
            '{\n'
            '  "name": "...",\n'
            '  "recipients_0_email": "sig1@ex.com",\n'
            '  "recipients_0_firstname": "Alice",\n'
            '  "recipients_1_email": "sig2@ex.com",\n'
            '  "recipients_1_firstname": "Bob"\n'
            '}\n\n'
            'Réponse : {"data": {"workflow_id": "wfl_xxx", "status": "draft"}}'
        ),
        parameters={
            'name': {
                'description': _('Nom du workflow Goodflag'),
                'example_value': 'Signature convention 2024-001',
            },
            'recipient_email': {
                'description': _('Email du signataire unique (format plat)'),
                'example_value': 'jean.dupont@example.com',
            },
            'recipient_firstname': {
                'description': _('Prénom du signataire'),
                'example_value': 'Jean',
            },
            'recipient_lastname': {
                'description': _('Nom du signataire'),
                'example_value': 'Dupont',
            },
            'recipient_phone': {
                'description': _('Téléphone du signataire pour SMS 2FA (format: +33612345678)'),
                'example_value': '+33612345678',
            },
            'external_ref': {
                'description': _('Référence externe Publik — numéro de demande'),
                'example_value': 'DEM-2024-001',
            },
            'recipients': {
                'description': _(
                    'Liste JSON de signataires : [{"email": "...", "firstName": "...", '
                    '"lastName": "...", "phoneNumber": "...", "consentPageId": "cop_xxx"}]'
                ),
                'example_value': '[{"email": "sig@ex.com", "firstName": "Jean", "lastName": "Dupont"}]',
            },
            'steps': {
                'description': _(
                    'Steps natifs Goodflag : [{"stepType": "approval|signature", '
                    '"recipients": [...], "maxInvites": 5}]'
                ),
                'example_value': '[{"stepType": "signature", "recipients": [{"email": "sig@ex.com", "firstName": "Jean", "lastName": "Dupont", "consentPageId": "cop_xxx"}]}]',
            },
            'metadata': {
                'description': _(
                    'Métadonnées Goodflag — champs data1 à data16 du mapping tenant. '
                    'Requiert default_layout_id configuré sur le connecteur.'
                ),
                'example_value': '{"data1": "DEM-2024-001", "data2": "Service urbanisme", "data3": "{{ form_user_nameid }}"}',
            },
            'workflow_mode': {
                'description': _('Mode du workflow (défaut: FULL)'),
                'example_value': 'FULL',
            },
            'layout_id': {
                'description': _('Layout Goodflag pour les métadonnées (défaut: valeur du connecteur)'),
                'example_value': 'lay_abc123',
            },
        },
    )
    def create_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

        name = self._get_param(payload, 'name')
        if not name:
            raise GoodflagValidationError("'name' is required")

        # Soit on fournit des steps natifs Goodflag, soit des recipients
        # simplifiés (JSON) ou des paramètres plats (form W.C.S.)
        steps_config = payload.get('steps')
        recipients = payload.get('recipients')

        # Multi-signataires (format indexé ou JSON) ou signataire unique (format plat)
        if not steps_config and not recipients:
            # Essayer le format multi (recipients_0_email, recipients_1_email, ...)
            recipients = self._parse_multi_recipients(payload)

        if not steps_config and not recipients:
            # Format plat : un seul signataire (recipient_email, ...)
            recipient_email = self._get_param(payload, 'recipient_email')
            if recipient_email:
                recipients = [{
                    'email': recipient_email,
                    'firstName': self._get_param(payload, 'recipient_firstname', ''),
                    'lastName': self._get_param(payload, 'recipient_lastname', ''),
                    'phone': self._get_param(payload, 'recipient_phone', ''),
                }]

        if not steps_config and not recipients:
            raise GoodflagValidationError(
                "'steps' or 'recipients' is required"
            )

        steps = self._build_steps(
            recipients=recipients or [],
            steps_config=steps_config,
        )

        # Métadonnées Publik -> champs data1-data16 Goodflag
        metadata = payload.get('metadata', {})
        external_ref = self._get_param(payload, 'external_ref', '')

        # Layout pour les métadonnées
        layout_id = self._get_param(payload, 'layout_id') or self.default_layout_id

        # Mode du workflow
        workflow_mode = self._get_param(payload, 'workflow_mode', 'FULL')

        # Co-managers
        allowed_comanager_users = payload.get('allowed_comanager_users')
        comanager_notified_events = payload.get('comanager_notified_events')

        if not self.user_id:
            raise GoodflagValidationError(
                "Configuration error: 'user_id' is missing in the connector settings."
            )

        client = self._get_client()
        result = client.create_workflow(
            user_id=self.user_id,
            name=name,
            steps=steps,
            description=payload.get('description', ''),
            workflow_mode=workflow_mode,
            notified_events=payload.get('notified_events'),
            watchers=payload.get('watchers'),
            template_id=payload.get('template_id'),
            allow_consolidation=payload.get('allow_consolidation'),
            layout_id=layout_id,
            metadata=metadata,
            external_ref=external_ref,
            allowed_comanager_users=allowed_comanager_users,
            comanager_notified_events=comanager_notified_events,
        )

        workflow_id = result.get('workflow_id')
        if not workflow_id:
            raise GoodflagError(
                "Goodflag API failed to return a workflow ID."
            )

        # Persistance locale
        GoodflagWorkflowTrace.objects.update_or_create(
            resource=self,
            goodflag_workflow_id=workflow_id,
            defaults={
                'external_ref': external_ref,
                'workflow_name': name,
                'status': result.get('status', 'draft'),
                'metadata_json': json.dumps(metadata),
            },
        )

        # Ne retourner que les champs essentiels (sans 'raw') pour éviter
        # que WCS ait à analyser une réponse trop volumineuse qui peut
        # empêcher la propagation correcte de goodflag_create_data_workflow_id.
        return {'data': {
            'workflow_id': workflow_id,
            'status': result.get('status', 'draft'),
        }}

    @endpoint(
        name='submit-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Crée, uploade le document et démarre un workflow Goodflag en un seul appel'),
        long_description=_(
            'Enchaîne automatiquement : création du workflow (draft), upload du document PDF, '
            'démarrage (envoi des invitations aux signataires). '
            'Remplace les 3 appels séparés create-workflow + upload-document + start-workflow.\n\n'
            'Exemple 1 — signataire unique avec fichier via URL (recommandé depuis W.C.S.) :\n'
            '{\n'
            '  "name": "Signature {{ form_var_objet_document }}",\n'
            '  "recipient_email": "{{ form_var_email_signataire }}",\n'
            '  "recipient_firstname": "{{ form_var_prenom_signataire }}",\n'
            '  "recipient_lastname": "{{ form_var_nom_signataire }}",\n'
            '  "recipient_phone": "{{ form_var_telephone_portable }}",\n'
            '  "external_ref": "{{ form_number }}",\n'
            '  "file_url": "{{ form_var_document_pdf_url }}",\n'
            '  "filename": "{{ form_var_document_pdf_filename }}"\n'
            '}\n\n'
            'Exemple 2 — fichier encodé en base64 :\n'
            '{\n'
            '  "name": "Signature {{ form_number }}",\n'
            '  "recipient_email": "{{ form_var_email_signataire }}",\n'
            '  "external_ref": "{{ form_number }}",\n'
            '  "file": {\n'
            '    "filename": "convention.pdf",\n'
            '    "content_type": "application/pdf",\n'
            '    "content": "{{ form_var_document_pdf|base64_encode }}"\n'
            '  }\n'
            '}\n\n'
            'Exemple 3 — multi-signataires avec métadonnées :\n'
            '{\n'
            '  "name": "Convention {{ form_number }}",\n'
            '  "recipients": [\n'
            '    {"email": "{{ form_var_email_sig1 }}", "firstName": "{{ form_var_prenom_sig1 }}", '
            '"lastName": "{{ form_var_nom_sig1 }}"},\n'
            '    {"email": "{{ form_var_email_sig2 }}", "firstName": "{{ form_var_prenom_sig2 }}", '
            '"lastName": "{{ form_var_nom_sig2 }}"}\n'
            '  ],\n'
            '  "external_ref": "{{ form_number }}",\n'
            '  "metadata": {"data1": "{{ form_number }}", "data2": "{{ form_var_service }}"},\n'
            '  "file_url": "{{ form_var_document_pdf_url }}"\n'
            '}\n\n'
            'Réponse : {"data": {"workflow_id": "wfl_xxx", "status": "started", "document_id": "doc_xxx"}}'
        ),
        parameters={
            'name': {
                'description': _('Nom du workflow Goodflag'),
                'example_value': 'Signature convention 2024-001',
            },
            'recipient_email': {
                'description': _('Email du signataire unique (format plat)'),
                'example_value': 'jean.dupont@example.com',
            },
            'recipient_firstname': {
                'description': _('Prénom du signataire'),
                'example_value': 'Jean',
            },
            'recipient_lastname': {
                'description': _('Nom du signataire'),
                'example_value': 'Dupont',
            },
            'recipient_phone': {
                'description': _('Téléphone du signataire pour SMS 2FA (format: +33612345678)'),
                'example_value': '+33612345678',
            },
            'external_ref': {
                'description': _('Référence externe Publik — numéro de demande'),
                'example_value': 'DEM-2024-001',
            },
            'recipients': {
                'description': _(
                    'Liste JSON de signataires : '
                    '[{"email": "...", "firstName": "...", "lastName": "...", '
                    '"phoneNumber": "...", "consentPageId": "cop_xxx"}]'
                ),
                'example_value': '[{"email": "sig@ex.com", "firstName": "Jean", "lastName": "Dupont"}]',
            },
            'steps': {
                'description': _(
                    'Steps natifs Goodflag pour approbation + signature : '
                    '[{"stepType": "approval|signature", "recipients": [...], "maxInvites": 5}]'
                ),
            },
            'file': {
                'description': _(
                    'Document à signer — objet JSON : '
                    '{"filename": "...", "content_type": "application/pdf", "content": "<base64>"}'
                ),
                'example_value': '{"filename": "document.pdf", "content_type": "application/pdf", "content": "<base64>"}',
            },
            'file_url': {
                'description': _('URL du document PDF à télécharger depuis Publik/WCS'),
                'example_value': '{{ form_var_document_pdf_url }}',
            },
            'file_base64': {
                'description': _('Contenu du document encodé en base64'),
            },
            'filename': {
                'description': _('Nom du fichier PDF (défaut: document.pdf)'),
                'example_value': 'convention.pdf',
            },
            'metadata': {
                'description': _(
                    'Métadonnées Goodflag (champs data1 à data16 du mapping tenant). '
                    'Requiert default_layout_id configuré sur le connecteur.'
                ),
                'example_value': '{"data1": "DEM-2024-001", "data2": "Service urbanisme"}',
            },
            'signature_profile_id': {
                'description': _('Profil de signature Goodflag (défaut: valeur du connecteur)'),
                'example_value': 'sip_abc123',
            },
            'workflow_mode': {
                'description': _('Mode du workflow (défaut: FULL)'),
                'example_value': 'FULL',
            },
        },
    )
    def submit_workflow(self, request, **kwargs):
        """
        Combine create-workflow + upload-document + start-workflow en un seul appel.
        """
        payload = self._parse_payload(request, **kwargs)

        # -- Étape 1 : Créer le workflow --
        name = self._get_param(payload, 'name')
        if not name:
            raise GoodflagValidationError("'name' is required")

        steps_config = payload.get('steps')
        recipients = payload.get('recipients')
        if not steps_config and not recipients:
            recipients = self._parse_multi_recipients(payload)
        if not steps_config and not recipients:
            recipient_email = self._get_param(payload, 'recipient_email')
            if recipient_email:
                recipients = [{
                    'email': recipient_email,
                    'firstName': self._get_param(payload, 'recipient_firstname', ''),
                    'lastName': self._get_param(payload, 'recipient_lastname', ''),
                    'phone': self._get_param(payload, 'recipient_phone', ''),
                }]
        if not steps_config and not recipients:
            raise GoodflagValidationError("'steps' or 'recipients' is required")

        steps = self._build_steps(recipients=recipients or [], steps_config=steps_config)
        metadata = payload.get('metadata', {})
        external_ref = self._get_param(payload, 'external_ref', '')
        layout_id = self._get_param(payload, 'layout_id') or self.default_layout_id
        workflow_mode = self._get_param(payload, 'workflow_mode', 'FULL')

        if not self.user_id:
            raise GoodflagValidationError(
                "Configuration error: 'user_id' is missing in the connector settings."
            )

        client = self._get_client()
        create_result = client.create_workflow(
            user_id=self.user_id,
            name=name,
            steps=steps,
            description=payload.get('description', ''),
            workflow_mode=workflow_mode,
            notified_events=payload.get('notified_events'),
            watchers=payload.get('watchers'),
            template_id=payload.get('template_id'),
            allow_consolidation=payload.get('allow_consolidation'),
            layout_id=layout_id,
            metadata=metadata,
            external_ref=external_ref,
            allowed_comanager_users=payload.get('allowed_comanager_users'),
            comanager_notified_events=payload.get('comanager_notified_events'),
        )

        workflow_id = create_result.get('workflow_id')
        if not workflow_id:
            raise GoodflagError("Goodflag API failed to return a workflow ID.")

        GoodflagWorkflowTrace.objects.update_or_create(
            resource=self,
            goodflag_workflow_id=workflow_id,
            defaults={
                'external_ref': external_ref,
                'workflow_name': name,
                'status': create_result.get('status', 'draft'),
                'metadata_json': json.dumps(metadata),
            },
        )

        # -- Étape 2 : Upload du document --
        # En cas d'échec ici ou à l'étape 3, la trace reste en statut 'draft'
        # avec un workflow_id valide : l'opérateur peut diagnostiquer via
        # l'admin Django ou relancer manuellement.
        signature_profile_id = (
            self._get_param(payload, 'signature_profile_id')
            or self.default_signature_profile_id
        )
        try:
            file_content, filename, content_type = self._parse_file_from_payload(payload, request)
            upload_result = client.upload_document(
                workflow_id=workflow_id,
                file_content=file_content,
                filename=filename,
                content_type=content_type,
                signature_profile_id=signature_profile_id or None,
            )
        except GoodflagError as exc:
            logger.error(
                "submit_workflow: upload failed for workflow %s (created but not started): %s",
                workflow_id, exc,
            )
            GoodflagWorkflowTrace.objects.filter(
                resource=self, goodflag_workflow_id=workflow_id,
            ).update(status='upload_failed', updated_at=timezone.now())
            raise

        doc_id = upload_result.get('document_id')
        if doc_id:
            GoodflagDocumentTrace.objects.create(
                resource=self,
                goodflag_workflow_id=workflow_id,
                goodflag_document_id=doc_id,
                filename=filename,
                content_type=content_type,
                document_type='sign',
                file_size=len(file_content),
            )

        # -- Étape 3 : Démarrer le workflow --
        try:
            start_result = client.start_workflow(workflow_id)
        except GoodflagError as exc:
            logger.error(
                "submit_workflow: start failed for workflow %s (created+uploaded but not started): %s",
                workflow_id, exc,
            )
            GoodflagWorkflowTrace.objects.filter(
                resource=self, goodflag_workflow_id=workflow_id,
            ).update(status='start_failed', updated_at=timezone.now())
            raise

        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=start_result.get('status', 'started'),
            updated_at=timezone.now(),
        )

        return {'data': {
            'workflow_id': workflow_id,
            'status': start_result.get('status', 'started'),
            'document_id': doc_id or '',
        }}

    @endpoint(
        name='upload-document',
        perm='can_access',
        methods=['post'],
        description=_('Upload un document dans un workflow Goodflag existant'),
        long_description=_(
            'Charge un document PDF/DOCX dans un workflow déjà créé. '
            'Le document peut être fourni de 4 façons :\n\n'
            '1. Objet JSON imbriqué (recommandé) :\n'
            '{\n'
            '  "workflow_id": "wfl_xxx",\n'
            '  "file": {\n'
            '    "filename": "convention.pdf",\n'
            '    "content_type": "application/pdf",\n'
            '    "content": "<base64>"\n'
            '  }\n'
            '}\n\n'
            '2. URL Publik (le serveur Passerelle télécharge le fichier) :\n'
            '{\n'
            '  "workflow_id": "wfl_xxx",\n'
            '  "file_url": "{{ form_var_document_pdf_url }}",\n'
            '  "filename": "convention.pdf"\n'
            '}\n\n'
            '3. Base64 directe :\n'
            '{"workflow_id": "wfl_xxx", "file_base64": "<base64>", "filename": "convention.pdf"}\n\n'
            '4. Multipart Django (champ "file" dans la requête multipart)\n\n'
            'Réponse : {"data": {"document_id": "doc_xxx", "workflow_id": "wfl_xxx", '
            '"filename": "convention.pdf", "documents": [...], "parts": [...]}}'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe Publik (alternative à workflow_id)'),
                'example_value': 'DEM-2024-001',
            },
            'file': {
                'description': _(
                    'Document à signer : objet JSON {"filename": "...", '
                    '"content_type": "application/pdf", "content": "<base64>"}'
                ),
                'example_value': '{"filename": "document.pdf", "content_type": "application/pdf", "content": "<base64>"}',
            },
            'file_url': {
                'description': _('URL du document à télécharger (depuis Publik/WCS)'),
                'example_value': '{{ form_var_document_pdf_url }}',
            },
            'file_base64': {
                'description': _('Contenu du document encodé en base64'),
            },
            'filename': {
                'description': _('Nom du fichier (défaut: document.pdf)'),
                'example_value': 'convention.pdf',
            },
            'content_type': {
                'description': _('Type MIME du fichier (défaut: application/pdf)'),
                'example_value': 'application/pdf',
            },
            'signature_profile_id': {
                'description': _('Profil de signature Goodflag (défaut: valeur du connecteur)'),
                'example_value': 'sip_abc123',
            },
        },
    )
    def upload_document(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        signature_profile_id = (
            self._get_param(payload, 'signature_profile_id')
            or self.default_signature_profile_id
        )

        file_content, filename, content_type = self._parse_file_from_payload(payload, request)

        client = self._get_client()
        result = client.upload_document(
            workflow_id=workflow_id,
            file_content=file_content,
            filename=filename,
            content_type=content_type,
            signature_profile_id=signature_profile_id or None,
        )

        # Trace du document
        doc_id = result.get('document_id')
        if doc_id:
            GoodflagDocumentTrace.objects.create(
                resource=self,
                goodflag_workflow_id=workflow_id,
                goodflag_document_id=doc_id,
                filename=filename,
                content_type=content_type,
                document_type='sign' if signature_profile_id else 'attachment',
                file_size=len(file_content),
            )

        return {'data': result}

    @endpoint(
        name='upload-documents',
        perm='can_access',
        methods=['post'],
        description=_('Upload plusieurs documents dans un workflow Goodflag'),
        long_description=_(
            'Charge plusieurs documents PDF/DOCX/Images dans un workflow '
            'existant en une seule requête multipart.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
            'files': {
                'description': _('Données des fichiers (JSON)'),
            },
        },
    )
    def upload_documents(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        files_data = payload.get('files', [])
        if not files_data:
            raise GoodflagValidationError("'files' list is required")

        files_list = []
        for f in files_data:
            content_b64 = f.get('file_base64')
            if not content_b64:
                continue

            if len(content_b64) > _MAX_B64_LEN:
                raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
            file_content = base64.b64decode(content_b64)
            content_type = f.get('content_type', 'application/pdf')
            content_type = _sniff_content_type(file_content, content_type)
            _validate_file_content(file_content, content_type)

            files_list.append({
                'content': file_content,
                'filename': f.get('filename', 'document.pdf'),
                'content_type': content_type,
                'signature_profile_id': (
                    f.get('signature_profile_id')
                    or self.default_signature_profile_id
                ),
            })

        if not files_list:
            raise GoodflagValidationError("No valid files found in 'files'")

        client = self._get_client()
        result = client.upload_documents(
            workflow_id=workflow_id,
            files_list=files_list,
        )

        # Traces des documents
        for doc in result.get('documents', []):
            GoodflagDocumentTrace.objects.create(
                resource=self,
                goodflag_workflow_id=workflow_id,
                goodflag_document_id=doc.get('id'),
                filename=doc.get('name', 'unknown'),
                document_type='sign',
            )

        return {'data': result}

    @endpoint(
        name='start-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Démarre un workflow Goodflag'),
        long_description=_(
            'Passe le statut du workflow à "started" via PATCH. '
            'Les destinataires de la première étape recevront leurs '
            'invitations par email.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def start_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        client = self._get_client()
        result = client.start_workflow(workflow_id)

        # Mise à jour de la trace
        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=result.get('status', 'started'),
            updated_at=timezone.now(),
        )

        # Ne retourner que les champs essentiels (sans 'raw') pour éviter
        # que WCS ait à analyser une réponse volumineuse.
        return {'data': {
            'workflow_id': result.get('workflow_id', workflow_id),
            'status': result.get('status', 'started'),
        }}

    @endpoint(
        name='get-workflow',
        perm='can_access',
        methods=['get'],
        description=_('Récupère le détail d\'un workflow Goodflag'),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def get_workflow(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        client = self._get_client()
        result = client.get_workflow(workflow_id)

        # Mise à jour de la trace locale
        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=result.get('status', ''),
            updated_at=timezone.now(),
        )

        return {'data': result}

    @endpoint(
        name='stop-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Arrête un workflow Goodflag'),
        long_description=_(
            'Passe le statut du workflow à "stopped". '
            'Les invitations en cours seront invalidées.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def stop_workflow(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            payload = self._parse_payload(request)
            workflow_id = self._resolve_workflow_id(payload)

        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        client = self._get_client()
        result = client.stop_workflow(workflow_id)

        # Mise à jour de la trace
        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=result.get('status', 'stopped'),
            updated_at=timezone.now(),
        )

        return {'data': result}

    @endpoint(
        name='archive-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Archive un workflow Goodflag'),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def archive_workflow(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            payload = self._parse_payload(request)
            workflow_id = self._resolve_workflow_id(payload)

        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        client = self._get_client()
        result = client.archive_workflow(workflow_id)

        # Mise à jour de la trace
        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=result.get('status', 'archived'),
            updated_at=timezone.now(),
        )

        return {'data': result}

    @endpoint(
        name='sync-status',
        perm='can_access',
        methods=['get'],
        description=_(
            'Récupère et normalise le statut d\'un workflow Goodflag '
            'en états simples exploitables par W.C.S.'
        ),
        long_description=_(
            'Interroge l\'API Goodflag et retourne un statut normalisé parmi :\n'
            '  draft     — workflow créé, pas encore démarré\n'
            '  started   — workflow en cours (invitations envoyées)\n'
            '  finished  — workflow terminé, document signé disponible\n'
            '  refused   — workflow arrêté ou refusé par un signataire\n'
            '  error     — statut inconnu ou erreur API\n\n'
            'Utilisation recommandée dans W.C.S. (pattern backoffice) :\n'
            '  URL : ?workflow_id={{ form_var_goodflag_workflow_id }}\n'
            '  varname : goodflag_status\n'
            '  Stocker dans champ backoffice :\n'
            '    goodflag_status_response_data_status → bo-goodflag-status\n'
            '  Condition de saut : form_var_goodflag_status == "finished"\n\n'
            'Le résultat est mis en cache (status_cache_ttl secondes) pour éviter '
            'des appels API répétitifs lors du polling. Les statuts finaux ne sont pas cachés.\n\n'
            'Réponse : {"data": {"workflow_id": "wfl_xxx", "raw_status": "finished", '
            '"status": "finished", "progress": 100, "is_final": true}}'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe Publik (alternative à workflow_id)'),
                'example_value': 'DEM-2024-001',
            },
        },
    )
    def sync_status(self, request, workflow_id=None, external_ref=None):
        """
        Endpoint utilitaire pour W.C.S. : retourne un statut normalisé
        parmi draft, started, pending, finished, refused, cancelled, error.
        """
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        # Cache statut pour éviter des appels API répétitifs
        cache_key = f'goodflag_status_{self.pk}_{workflow_id}'
        cached = None
        if self.status_cache_ttl > 0:
            cached = cache.get(cache_key)

        if cached is not None:
            logger.debug(
                "sync_status: cache hit for workflow %s (status=%s)",
                workflow_id, cached.get('status'),
            )
            return {'data': cached}

        client = self._get_client()
        result = client.get_workflow(workflow_id)

        normalized = result.get('normalized_status', 'error')
        raw_status = result.get('status', '')

        logger.info(
            "sync_status: workflow %s — workflowStatus=%s (normalisé=%s)",
            workflow_id, raw_status, normalized,
        )

        # Mise à jour trace
        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=normalized,
            updated_at=timezone.now(),
        )

        # Mise en cache du résultat
        is_final = normalized in _FINAL_STATUSES
        response_data = {
            'workflow_id': workflow_id,
            'raw_status': raw_status,
            'status': normalized,
            'progress': result.get('progress', 0),
            'is_final': is_final,
        }
        if self.status_cache_ttl > 0 and not is_final:
            cache.set(cache_key, response_data, timeout=self.status_cache_ttl)

        return {'data': response_data}

    @endpoint(
        name='create-invite',
        perm='can_access',
        methods=['post'],
        description=_('Crée une invitation pour un destinataire'),
        long_description=_(
            'Génère une URL d\'invitation pour un signataire ou '
            'approbateur d\'un workflow en cours. Utile pour envoyer '
            'les invitations depuis Publik plutôt que par Goodflag.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
            'recipient_email': {
                'description': _('Email du destinataire'),
            },
            'recipient_phone': {
                'description': _('Téléphone du destinataire (pour SMS 2FA)'),
            },
        },
    )
    def create_invite(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        recipient_email = self._get_param(payload, 'recipient_email')
        if not recipient_email:
            raise GoodflagValidationError("'recipient_email' is required")

        recipient_phone = self._get_param(payload, 'recipient_phone')

        client = self._get_client()
        result = client.create_invite(
            workflow_id, 
            recipient_email,
            recipient_phone=recipient_phone
        )

        return {'data': result}

    @endpoint(
        name='download-signed-documents',
        perm='can_access',
        methods=['get'],
        description=_('Télécharge les documents signés d\'un workflow terminé'),
        long_description=_(
            'Télécharge les documents signés via GET /downloadDocuments. '
            'Retourne un PDF unique ou un ZIP si plusieurs documents. '
            'Le contenu est retourné directement en réponse HTTP binaire.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def download_signed_documents(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        # Pas de pré-vérification du statut ici : c'est la condition de saut
        # WCS (<type>django</type>) qui contrôle la transition.
        # Si Goodflag refuse le download (workflow pas terminé),
        # l'API renverra une erreur HTTP que l'on propage.
        client = self._get_client()
        try:
            result = client.download_documents(workflow_id, streaming=True)
        except GoodflagError as exc:
            logger.warning(
                "download_signed_documents: échec pour workflow %s: %s",
                workflow_id, exc,
            )
            raise

        if 'response' in result:
            streaming_response = StreamingHttpResponse(
                result['response'].iter_content(chunk_size=8192),
                content_type=result['content_type'],
            )
            streaming_response['Content-Disposition'] = (
                f'attachment; filename="{result["filename"]}"'
            )
            return streaming_response

        response = HttpResponse(
            result.get('content', b''),
            content_type=result['content_type'],
        )
        response['Content-Disposition'] = (
            f'attachment; filename="{result["filename"]}"'
        )
        return response

    @endpoint(
        name='get-viewer-url',
        perm='can_access',
        methods=['post', 'get'],
        description=_(
            'Génère une URL de viewer pour un document Goodflag'
        ),
        long_description=_(
            'Permet d\'ouvrir le document dans le navigateur pour '
            'visualisation ou placement des champs de signature.'
        ),
        parameters={
            'document_id': {
                'description': _('Identifiant du document Goodflag'),
                'example_value': 'doc_abc123',
            },
            'redirect_url': {
                'description': _('URL de redirection après fermeture du viewer'),
            },
        },
    )
    def get_viewer_url(self, request, document_id=None, redirect_url=None, expired=None):
        if not document_id:
            raise GoodflagValidationError("'document_id' is required")

        client = self._get_client()
        result = client.get_document_viewer_url(
            document_id=document_id,
            redirect_url=redirect_url,
            expired=expired,
        )

        return {'data': result}

    @endpoint(
        name='download-evidence',
        perm='can_access',
        methods=['get'],
        description=_(
            'Télécharge le certificat de preuve d\'un workflow terminé'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
        },
    )
    def download_evidence(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        client = self._get_client()
        result = client.download_evidence_certificate(workflow_id, streaming=True)

        if 'response' in result:
            # Mode streaming
            streaming_response = StreamingHttpResponse(
                result['response'].iter_content(chunk_size=8192),
                content_type=result['content_type'],
            )
            streaming_response['Content-Disposition'] = (
                f'attachment; filename="{result["filename"]}"'
            )
            return streaming_response

        response = HttpResponse(
            result['content'],
            content_type=result['content_type'],
        )
        response['Content-Disposition'] = (
            f'attachment; filename="{result["filename"]}"'
        )
        return response

    @endpoint(
        name='webhook',
        perm='open',
        methods=['post'],
        description=_('Reçoit les notifications webhook de Goodflag'),
        long_description=_(
            'Endpoint public pour recevoir les événements webhook '
            'Goodflag. Sécurisé par re-validation via l\'API '
            'webhookEvents de Goodflag (Goodflag ne signe pas ses '
            'webhooks par HMAC). Idempotent par event_id.'
        ),
    )
    def webhook(self, request):
        """
        Endpoint webhook pour recevoir les notifications Goodflag.

        Sécurité :
        - Goodflag ne signe pas ses webhooks (pas de HMAC).
        - On valide par token dans l'URL (webhook_secret) et/ou
          par re-validation via l'API webhookEvents.
        - Idempotence par event_id unique.
        - Journalisation complète.
        """
        # Validation par token URL si configuré
        if self.webhook_secret:
            provided_token = request.GET.get('token', '')
            if not hmac.compare_digest(provided_token, self.webhook_secret):
                logger.warning(
                    "Webhook token validation failed: got=%s",
                    provided_token[:4] + '...' if provided_token else '(empty)',
                )
                return JsonResponse({'error': 'Invalid token'}, status=403)

        try:
            payload = json.loads(request.body)
        except (ValueError, TypeError):
            logger.warning("Webhook received with invalid JSON body")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Structure du webhook event Goodflag
        event_id = payload.get('id', '')
        event_type = payload.get('eventType', '')
        workflow_id = payload.get('workflowId', '')

        # Rejeter les webhooks sans event_id : sans lui, impossible d'assurer
        # l'idempotence (anti-rejeu) ni la re-validation via l'API Goodflag.
        if not event_id:
            logger.warning("Webhook received without event_id, rejecting")
            return JsonResponse({'error': 'Missing event id'}, status=400)
        webhook_id = payload.get('webhookId', '')
        step_id = payload.get('stepId', '')
        created = payload.get('created', '')

        logger.info(
            "Webhook received: event_id=%s, event_type=%s, workflow_id=%s",
            event_id, event_type, workflow_id
        )

        # Anti-rejeu : vérifier si cet événement a déjà été traité
        if event_id:
            already_exists = GoodflagWebhookEvent.objects.filter(
                resource=self,
                event_id=event_id,
            ).exists()
            if already_exists:
                logger.info(
                    "Webhook event already processed, skipping: event_id=%s",
                    event_id
                )
                return JsonResponse({'status': 'already_processed'})

        # Re-validation via l'API Goodflag : vérifier que l'événement
        # existe réellement dans Goodflag
        raw_status = ''
        normalized_status = ''
        if event_id and workflow_id:
            try:
                client = self._get_client()
                # Vérifier l'événement via l'API webhookEvents
                verified_event = client.get_webhook_event(event_id)
                if verified_event.get('workflowId') != workflow_id:
                    logger.warning(
                        "Webhook event workflowId mismatch: "
                        "received=%s, verified=%s",
                        workflow_id, verified_event.get('workflowId')
                    )
                    return JsonResponse(
                        {'error': 'Event verification failed'}, status=403
                    )

                # Récupérer le statut actuel du workflow
                wf_data = client.get_workflow(workflow_id)
                raw_status = wf_data.get('status', '')
                normalized_status = wf_data.get('normalized_status', '')
            except GoodflagError as exc:
                logger.warning(
                    "Failed to re-validate webhook via API: %s", exc
                )
                # On accepte quand même l'événement mais on le note
                raw_status = 'unverified'
                normalized_status = 'error'

        # Enregistrement de l'événement
        GoodflagWebhookEvent.objects.create(
            resource=self,
            event_id=event_id,
            event_type=event_type,
            goodflag_workflow_id=workflow_id,
            webhook_id=webhook_id,
            step_id=step_id,
            raw_status=raw_status,
            normalized_status=normalized_status,
            payload_json=json.dumps(payload),
            timestamp_goodflag=str(created),
        )

        # Mise à jour de la trace workflow
        if workflow_id and normalized_status:
            GoodflagWorkflowTrace.objects.filter(
                resource=self,
                goodflag_workflow_id=workflow_id,
            ).update(
                status=normalized_status,
                updated_at=timezone.now(),
            )

        # Notification WCS si événement significatif
        if event_type in self._NOTIFY_EVENT_TYPES:
            self._notify_wcs(workflow_id, event_type, normalized_status, event_id)

        return JsonResponse({'status': 'ok'})

    @endpoint(
        name='retrieve-by-external-ref',
        perm='can_access',
        methods=['get'],
        description=_(
            'Retrouve un workflow Goodflag à partir d\'une référence '
            'externe Publik'
        ),
        parameters={
            'external_ref': {
                'description': _(
                    'Référence externe (ex: numéro de demande Publik)'
                ),
                'example_value': 'DEMANDE-2024-001',
            },
        },
    )
    def retrieve_by_external_ref(self, request, external_ref):
        if not external_ref:
            raise GoodflagValidationError("'external_ref' is required")

        traces = GoodflagWorkflowTrace.objects.filter(
            resource=self,
            external_ref=external_ref,
        ).order_by('-created_at')

        results = []
        for trace in traces:
            results.append({
                'workflow_id': trace.goodflag_workflow_id,
                'workflow_name': trace.workflow_name,
                'external_ref': trace.external_ref,
                'status': trace.status,
                'created_at': trace.created_at.isoformat(),
                'updated_at': trace.updated_at.isoformat(),
            })

        return {
            'data': {
                'count': len(results),
                'results': results,
            }
        }

    @endpoint(
        name='resend-invite',
        perm='can_access',
        methods=['post'],
        description=_('Renvoie une invitation par email à un destinataire'),
        long_description=_(
            'Envoie ou ré-envoie une invitation email à un signataire. '
            'Utile pour relancer un signataire qui n\'a pas reçu ou lu '
            'son invitation initiale depuis W.C.S.'
        ),
        parameters={
            'workflow_id': {
                'description': _('Identifiant du workflow Goodflag'),
                'example_value': 'wfl_abc123',
            },
            'external_ref': {
                'description': _('Référence externe (ID Publik/WCS)'),
            },
            'recipient_email': {
                'description': _('Email du destinataire à qui renvoyer l\'invitation'),
            },
        },
    )
    def resend_invite(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

        recipient_email = self._get_param(payload, 'recipient_email')
        if not recipient_email:
            raise GoodflagValidationError("'recipient_email' is required")

        client = self._get_client()
        result = client.send_invite(workflow_id, recipient_email)

        return {'data': result}

    @endpoint(
        name='list-workflows',
        perm='can_access',
        methods=['get'],
        description=_('Liste et recherche les workflows Goodflag'),
        long_description=_(
            'Recherche dans les workflows Goodflag avec filtres optionnels. '
            'Utile pour diagnostiquer les workflows bloqués ou pour la '
            'supervision depuis W.C.S.'
        ),
        parameters={
            'text': {
                'description': _('Texte de recherche (nom du workflow)'),
            },
            'status': {
                'description': _('Filtre par statut (draft, started, finished, stopped)'),
            },
            'page': {
                'description': _('Index de page (0-based, défaut 0)'),
            },
            'per_page': {
                'description': _('Éléments par page (défaut 50, max 100)'),
            },
        },
    )
    def list_workflows(self, request, **kwargs):
        params = request.GET
        text = params.get('text')
        status_filter = params.get('status')
        try:
            page_index = int(params.get('page', 0))
        except (TypeError, ValueError):
            page_index = 0
        try:
            items_per_page = min(int(params.get('per_page', 50)), 100)
        except (TypeError, ValueError):
            items_per_page = 50

        # Mapping statut normalisé Publik → statut brut Goodflag
        _REVERSE_STATUS_MAP = {
            'refused': 'stopped',
            'finished': 'finished',
            'started': 'started',
            'draft': 'draft',
            'error': 'stopped',
        }
        filters = {}
        if status_filter:
            filters['workflowStatus'] = _REVERSE_STATUS_MAP.get(
                status_filter, status_filter
            )

        client = self._get_client()
        result = client.search_workflows(
            text=text,
            items_per_page=items_per_page,
            page_index=page_index,
            filters=filters,
        )

        return {
            'data': {
                'total': result.get('totalItems', 0),
                'page': page_index,
                'per_page': items_per_page,
                'items': [
                    {
                        'workflow_id': wf.get('id'),
                        'name': wf.get('name'),
                        'status': wf.get('workflowStatus'),
                        'progress': wf.get('progress', 0),
                        'created': wf.get('created'),
                        'updated': wf.get('updated'),
                    }
                    for wf in result.get('items', [])
                ],
            }
        }


# ====================================================================== #
# Modèles de persistance locale
# ====================================================================== #


class GoodflagWorkflowTrace(models.Model):
    """
    Corrélation entre un workflow Goodflag et une demande Publik.

    Permet de :
    - retrouver un workflow par sa référence externe Publik
    - suivre le statut courant sans appeler l'API Goodflag
    - prévenir les créations de doublons
    - fournir un historique minimal
    """

    resource = models.ForeignKey(
        GoodflagResource,
        on_delete=models.CASCADE,
        related_name='workflow_traces',
        verbose_name=_('Connecteur'),
    )

    goodflag_workflow_id = models.CharField(
        _('ID workflow Goodflag'),
        max_length=256,
        db_index=True,
    )

    external_ref = models.CharField(
        _('Référence externe Publik'),
        max_length=512,
        blank=True,
        default='',
        db_index=True,
        help_text=_('Numéro de demande, identifiant usager, etc.'),
    )

    workflow_name = models.CharField(
        _('Nom du workflow'),
        max_length=512,
        blank=True,
        default='',
    )

    status = models.CharField(
        _('Statut courant'),
        max_length=64,
        blank=True,
        default='draft',
    )

    metadata_json = models.TextField(
        _('Métadonnées (JSON)'),
        blank=True,
        default='{}',
    )

    created_at = models.DateTimeField(
        _('Date de création'),
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        _('Dernière mise à jour'),
        auto_now=True,
    )

    class Meta:
        verbose_name = _('Trace workflow Goodflag')
        verbose_name_plural = _('Traces workflow Goodflag')
        unique_together = [('resource', 'goodflag_workflow_id')]
        indexes = [
            models.Index(
                fields=['resource', 'external_ref'],
                name='gf_wf_resource_extref_idx',
            ),
        ]

    def __str__(self):
        return (
            f'Workflow {self.goodflag_workflow_id} '
            f'({self.external_ref}) - {self.status}'
        )


class GoodflagWebhookEvent(models.Model):
    """
    Journal des événements webhook reçus de Goodflag.

    Permet de :
    - assurer l'idempotence (anti-rejeu)
    - tracer l'historique des notifications
    - diagnostiquer les problèmes d'intégration
    """

    resource = models.ForeignKey(
        GoodflagResource,
        on_delete=models.CASCADE,
        related_name='webhook_events',
        verbose_name=_('Connecteur'),
    )

    event_id = models.CharField(
        _('ID événement Goodflag'),
        max_length=256,
        blank=True,
        default='',
        db_index=True,
        help_text=_('Format: wbe_xxx'),
    )

    event_type = models.CharField(
        _('Type d\'événement'),
        max_length=128,
        blank=True,
        default='',
        help_text=_(
            'Ex: workflowStarted, workflowFinished, workflowStopped, '
            'recipientFinished, recipientRefused, commentCreated'
        ),
    )

    goodflag_workflow_id = models.CharField(
        _('ID workflow Goodflag'),
        max_length=256,
        blank=True,
        default='',
        db_index=True,
    )

    webhook_id = models.CharField(
        _('ID webhook Goodflag'),
        max_length=256,
        blank=True,
        default='',
        help_text=_('Format: wbh_xxx'),
    )

    step_id = models.CharField(
        _('ID étape Goodflag'),
        max_length=256,
        blank=True,
        default='',
        help_text=_('Format: stp_xxx'),
    )

    raw_status = models.CharField(
        _('Statut brut Goodflag'),
        max_length=64,
        blank=True,
        default='',
    )

    normalized_status = models.CharField(
        _('Statut normalisé'),
        max_length=32,
        blank=True,
        default='',
    )

    payload_json = models.TextField(
        _('Payload JSON complet'),
        blank=True,
        default='{}',
    )

    timestamp_goodflag = models.CharField(
        _('Timestamp Goodflag'),
        max_length=64,
        blank=True,
        default='',
    )

    received_at = models.DateTimeField(
        _('Date de réception'),
        auto_now_add=True,
    )

    class Meta:
        verbose_name = _('Événement webhook Goodflag')
        verbose_name_plural = _('Événements webhook Goodflag')
        indexes = [
            models.Index(
                fields=['resource', 'event_id'],
                name='gf_webhook_resource_evtid_idx',
            ),
            models.Index(
                fields=['resource', 'goodflag_workflow_id'],
                name='gf_webhook_resource_wfid_idx',
            ),
        ]

    def __str__(self):
        return (
            f'Event {self.event_id} ({self.event_type}) '
            f'for workflow {self.goodflag_workflow_id}'
        )


class GoodflagDocumentTrace(models.Model):
    """
    Métadonnées des documents uploadés ou signés dans Goodflag.

    Permet de :
    - retrouver les documents associés à un workflow
    - tracer les uploads
    - conserver les métadonnées sans stocker le contenu binaire
    """

    resource = models.ForeignKey(
        GoodflagResource,
        on_delete=models.CASCADE,
        related_name='document_traces',
        verbose_name=_('Connecteur'),
    )

    goodflag_workflow_id = models.CharField(
        _('ID workflow Goodflag'),
        max_length=256,
        db_index=True,
    )

    goodflag_document_id = models.CharField(
        _('ID document Goodflag'),
        max_length=256,
        blank=True,
        default='',
        help_text=_('Format: doc_xxx'),
    )

    filename = models.CharField(
        _('Nom du fichier'),
        max_length=512,
        blank=True,
        default='',
    )

    content_type = models.CharField(
        _('Type MIME'),
        max_length=128,
        default='application/pdf',
    )

    document_type = models.CharField(
        _('Type de document'),
        max_length=32,
        default='sign',
        help_text=_('sign = à signer, attachment = pièce jointe'),
    )

    file_size = models.PositiveIntegerField(
        _('Taille du fichier (octets)'),
        default=0,
    )

    uploaded_at = models.DateTimeField(
        _('Date d\'upload'),
        auto_now_add=True,
    )

    class Meta:
        verbose_name = _('Trace document Goodflag')
        verbose_name_plural = _('Traces document Goodflag')
        indexes = [
            models.Index(
                fields=['resource', 'goodflag_workflow_id'],
                name='gf_doc_resource_wfid_idx',
            ),
        ]

    def __str__(self):
        return (
            f'Document {self.goodflag_document_id} '
            f'({self.filename}) in workflow {self.goodflag_workflow_id}'
        )
