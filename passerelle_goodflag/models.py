"""
Connecteur Passerelle pour la signature électronique Goodflag.
"""

import base64
import hmac
import io
import ipaddress
import json
import logging
import zipfile
from datetime import timedelta
from urllib.parse import unquote, urlparse

from django.core.cache import cache
from django.db import models
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from passerelle.base.models import BaseResource
from passerelle.utils.api import endpoint

from .client import GoodflagClient
from .exceptions import (
    GoodflagError,
    GoodflagRateLimitError,
    GoodflagValidationError,
)

logger = logging.getLogger(__name__)

_FINAL_STATUSES = frozenset({'finished', 'refused'})
_MAX_B64_LEN = int(50 * 1024 * 1024 * 4 / 3) + 1024  # ~50 Mo décodé

_PII_KEYS = frozenset({
    'recipient_email', 'recipient_phone', 'recipient_firstname',
    'recipient_lastname', 'email', 'firstName', 'lastName',
    'phoneNumber', 'phone', 'file', 'file_base64', 'file_url',
    'content',
})


def _sniff_content_type(content, declared_type):
    """Détecte le type MIME réel par magic bytes (WCS déclare souvent un type incorrect)."""
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
    """Rejette les URLs pointant vers des ressources internes (SSRF)."""
    if not url:
        raise GoodflagValidationError("file_url is required")
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise GoodflagValidationError(
            f"file_url scheme '{parsed.scheme}' not allowed (http/https only)"
        )
    hostname = parsed.hostname or ''
    try:
        addr = ipaddress.ip_address(hostname)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            raise GoodflagValidationError(
                f"file_url points to a non-routable address: {hostname}"
            )
    except ValueError:
        pass  # nom de domaine, pas une IP littérale
    local_patterns = ('localhost', '127.', '0.0.0.0', '::1', 'metadata.google',
                      '169.254.', 'metadata.internal')
    for pat in local_patterns:
        if hostname.lower().startswith(pat) or hostname.lower() == pat.rstrip('.'):
            raise GoodflagValidationError(
                f"file_url points to a local/internal address: {hostname}"
            )


def _validate_file_content(content, content_type):
    """Valide le contenu du fichier (magic bytes, chiffrement PDF, structure DOCX)."""
    if not content:
        raise GoodflagValidationError("Le fichier est vide")

    is_pdf_by_content = content.startswith(b'%PDF')
    is_pdf_by_type = 'pdf' in content_type.lower()

    if is_pdf_by_content or is_pdf_by_type:
        if is_pdf_by_type and not is_pdf_by_content:
            raise GoodflagValidationError(
                "Le fichier n'est pas un PDF valide (signature %PDF manquante). "
                "Vérifiez que l'URL du document est accessible et retourne bien un PDF."
            )
        # /Encrypt dans le header ou le trailer PDF => chiffrement
        probe = content[:2048] + content[-512:]
        if b'/Encrypt' in probe:
            raise GoodflagValidationError(
                "Le PDF est protégé par chiffrement. "
                "Goodflag ne peut pas signer un PDF chiffré. "
                "Déchiffrez le document avant de l'uploader."
            )

    elif 'wordprocessingml' in content_type or 'docx' in content_type.lower():
        if not content.startswith(b'PK\x03\x04'):
            raise GoodflagValidationError(
                "Le fichier DOCX n'est pas valide (signature ZIP manquante)"
            )
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
    """Connecteur Passerelle pour la signature électronique Goodflag."""

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

    category = _('Connecteurs métiers')

    class Meta:
        verbose_name = _('Connecteur Goodflag (signature électronique)')
        verbose_name_plural = _('Connecteurs Goodflag (signature électronique)')

    # Params d'auth Passerelle à exclure de la lecture du payload
    _PASSERELLE_AUTH_PARAMS = frozenset({'orig', 'algo', 'timestamp', 'nonce', 'signature'})

    def _parse_payload(self, request, **kwargs):
        """Combine query string, body (JSON ou form-encoded) et kwargs en un seul dict."""
        content_type = request.content_type or ''
        body = request.body

        payload = {}

        data_params = {
            k: v
            for k, v in request.GET.lists()
            if k not in self._PASSERELLE_AUTH_PARAMS
        }
        for k, v in data_params.items():
            payload[k] = v[0] if len(v) == 1 else v

        if 'application/json' in content_type:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({
                        k: v for k, v in body_data.items()
                        if k not in self._PASSERELLE_AUTH_PARAMS
                    })
            except (ValueError, TypeError):
                if not payload:
                    raise GoodflagValidationError("Invalid JSON body")
        elif request.POST:
            for k, v in request.POST.lists():
                if k not in self._PASSERELLE_AUTH_PARAMS:
                    payload[k] = v[0] if len(v) == 1 else v
        elif body:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({
                        k: v for k, v in body_data.items()
                        if k not in self._PASSERELLE_AUTH_PARAMS
                    })
            except (ValueError, TypeError):
                pass

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
        """Récupère un paramètre, déplie les listes form-encoded."""
        val = payload.get(key, default)
        if isinstance(val, list):
            val = val[0] if val else default
        if val == '' and default is not None:
            return default
        return val

    def _get_client(self):
        return GoodflagClient(
            base_url=self.base_url,
            access_token=self.access_token,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )

    def _log_debug(self, message, *args):
        if self.debug_mode:
            logger.info("[GOODFLAG DEBUG] " + message, *args)

    def _resolve_workflow_id(self, payload):
        """Résout workflow_id, avec fallback sur external_ref via la trace locale."""
        workflow_id = self._get_param(payload, 'workflow_id')
        if not workflow_id:
            external_ref = (
                self._get_param(payload, 'external_ref')
                or self._get_param(payload, 'display_id')
                or self._get_param(payload, 'uuid')
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
        """Construit la structure steps[] pour l'API Goodflag."""
        if steps_config:
            for step in steps_config:
                for recipient in step.get('recipients', []):
                    if not recipient.get('consentPageId') and self.default_consent_page_id:
                        recipient['consentPageId'] = self.default_consent_page_id
            return steps_config

        built_recipients = []
        for r in recipients:
            recipient = dict(r)
            if not recipient.get('consentPageId') and self.default_consent_page_id:
                recipient['consentPageId'] = self.default_consent_page_id
            if 'consentPageId' in recipient and not recipient['consentPageId']:
                del recipient['consentPageId']

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
        """Parse les destinataires (format JSON ou indexé WCS : recipients_0_email, etc.)."""
        recipients_raw = payload.get('recipients')
        if recipients_raw and isinstance(recipients_raw, list):
            return recipients_raw

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

    def _parse_file_from_payload(self, payload, request):
        """Extrait le fichier depuis le payload (JSON, multipart, base64, URL ou fields WCS)."""
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
            path = urlparse(file_url).path
            filename = unquote(path.rstrip('/').rsplit('/', 1)[-1]) or ''
        filename = filename or 'document.pdf'

        return file_content, filename, content_type

    _NOTIFY_EVENT_TYPES = frozenset({
        'workflowFinished', 'workflowStopped', 'workflowStarted',
        'recipientFinished', 'recipientRefused',
    })

    def _notify_wcs(self, workflow_id, event_type, normalized_status, event_id=''):
        """Notifie WCS d'un changement de statut via publik_callback_url."""
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

    def check_status(self):
        """Vérifie la disponibilité de l'API Goodflag."""
        client = self._get_client()
        result = client.test_connection()
        if result.get('status') != 'ok':
            raise GoodflagError(result.get('message', 'Goodflag API unreachable'))

    def hourly(self):
        """Synchronise les statuts des workflows actifs."""
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
                    "Hourly sync: rate limited on workflow %s (retry_after=%ds), stopping",
                    trace.goodflag_workflow_id, wait,
                )
                break
            except GoodflagError as exc:
                logger.warning(
                    "Hourly sync failed for workflow %s: %s",
                    trace.goodflag_workflow_id, exc,
                )

    def daily(self):
        """Purge les traces plus anciennes que retention_days."""
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

    @endpoint(
        name='create-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Crée un workflow de signature Goodflag (statut draft)'),
        long_description=_(
            'Crée un workflow en statut "draft". Accepte les signataires en format '
            'plat (recipient_email), JSON (recipients: [...]), indexé WCS '
            '(recipients_0_email) ou steps natifs Goodflag.'
        ),
        parameters={
            'name': {'description': _('Nom du workflow'), 'example_value': 'Signature convention 2024-001'},
            'recipient_email': {'description': _('Email du signataire (format plat)'), 'example_value': 'jean.dupont@example.com'},
            'recipient_firstname': {'description': _('Prénom du signataire'), 'example_value': 'Jean'},
            'recipient_lastname': {'description': _('Nom du signataire'), 'example_value': 'Dupont'},
            'recipient_phone': {'description': _('Téléphone 2FA (+33612345678)'), 'example_value': '+33612345678'},
            'external_ref': {'description': _('Référence externe Publik'), 'example_value': 'DEM-2024-001'},
            'recipients': {'description': _('Liste JSON de signataires')},
            'steps': {'description': _('Steps natifs Goodflag (approval/signature)')},
            'metadata': {'description': _('Métadonnées data1-data16 (nécessite default_layout_id)')},
            'workflow_mode': {'description': _('Mode du workflow (défaut: FULL)'), 'example_value': 'FULL'},
            'layout_id': {'description': _('Layout pour les métadonnées'), 'example_value': 'lay_abc123'},
        },
    )
    def create_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

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
            raise GoodflagValidationError(
                "'steps' or 'recipients' is required"
            )

        steps = self._build_steps(
            recipients=recipients or [],
            steps_config=steps_config,
        )

        metadata = payload.get('metadata', {})
        external_ref = self._get_param(payload, 'external_ref', '')
        layout_id = self._get_param(payload, 'layout_id') or self.default_layout_id
        workflow_mode = self._get_param(payload, 'workflow_mode', 'FULL')
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

        return {'data': {
            'workflow_id': workflow_id,
            'status': result.get('status', 'draft'),
        }}

    @endpoint(
        name='submit-workflow',
        perm='can_access',
        methods=['post'],
        description=_('Crée, uploade et démarre un workflow en un seul appel'),
        long_description=_(
            'Enchaîne create-workflow + upload-document + start-workflow. '
            'Le fichier peut être fourni via file_url, file (JSON base64), '
            'file_base64 ou multipart.'
        ),
        parameters={
            'name': {'description': _('Nom du workflow'), 'example_value': 'Signature convention 2024-001'},
            'recipient_email': {'description': _('Email du signataire (format plat)'), 'example_value': 'jean.dupont@example.com'},
            'recipient_firstname': {'description': _('Prénom du signataire'), 'example_value': 'Jean'},
            'recipient_lastname': {'description': _('Nom du signataire'), 'example_value': 'Dupont'},
            'recipient_phone': {'description': _('Téléphone 2FA'), 'example_value': '+33612345678'},
            'external_ref': {'description': _('Référence externe Publik'), 'example_value': 'DEM-2024-001'},
            'recipients': {'description': _('Liste JSON de signataires')},
            'steps': {'description': _('Steps natifs Goodflag')},
            'file': {'description': _('Document JSON : {"filename": "...", "content_type": "...", "content": "<base64>"}')},
            'file_url': {'description': _('URL du document PDF (téléchargé par Passerelle)')},
            'file_base64': {'description': _('Document encodé en base64')},
            'filename': {'description': _('Nom du fichier (défaut: document.pdf)'), 'example_value': 'convention.pdf'},
            'metadata': {'description': _('Métadonnées data1-data16')},
            'signature_profile_id': {'description': _('Profil de signature'), 'example_value': 'sip_abc123'},
            'workflow_mode': {'description': _('Mode du workflow (défaut: FULL)')},
        },
    )
    def submit_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)

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
        description=_('Upload un document dans un workflow existant'),
        long_description=_(
            'Accepte le fichier via JSON (file), multipart, base64 (file_base64) '
            'ou URL (file_url téléchargée par Passerelle).'
        ),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe (alternative à workflow_id)')},
            'file': {'description': _('Document JSON : {"filename", "content_type", "content"}')},
            'file_url': {'description': _('URL du document à télécharger')},
            'file_base64': {'description': _('Document encodé en base64')},
            'filename': {'description': _('Nom du fichier'), 'example_value': 'convention.pdf'},
            'content_type': {'description': _('Type MIME (défaut: application/pdf)')},
            'signature_profile_id': {'description': _('Profil de signature'), 'example_value': 'sip_abc123'},
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
        description=_('Upload plusieurs documents dans un workflow'),
        parameters={
            'workflow_id': {'description': _('ID du workflow')},
            'external_ref': {'description': _('Référence externe Publik')},
            'files': {'description': _('Liste des fichiers (JSON)')},
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
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
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

        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=result.get('status', 'started'),
            updated_at=timezone.now(),
        )

        return {'data': {
            'workflow_id': result.get('workflow_id', workflow_id),
            'status': result.get('status', 'started'),
        }}

    @endpoint(
        name='get-workflow',
        perm='can_access',
        methods=['get'],
        description=_('Récupère le détail d\'un workflow'),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
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
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
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
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
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
        description=_('Statut normalisé d\'un workflow (draft/started/finished/refused/error)'),
        long_description=_(
            'Retourne un statut simplifié pour WCS. '
            'Résultat mis en cache (status_cache_ttl secondes, sauf statuts finaux).'
        ),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
        },
    )
    def sync_status(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

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

        GoodflagWorkflowTrace.objects.filter(
            resource=self,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=normalized,
            updated_at=timezone.now(),
        )

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
        parameters={
            'workflow_id': {'description': _('ID du workflow')},
            'external_ref': {'description': _('Référence externe Publik')},
            'recipient_email': {'description': _('Email du destinataire')},
            'recipient_phone': {'description': _('Téléphone 2FA')},
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
        description=_('Télécharge les documents signés'),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
        },
    )
    def download_signed_documents(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError(
                "'workflow_id' or 'external_ref' is required"
            )

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
        description=_('Génère une URL de viewer pour un document'),
        parameters={
            'document_id': {'description': _('ID du document'), 'example_value': 'doc_abc123'},
            'redirect_url': {'description': _('URL de redirection après fermeture')},
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
        description=_('Télécharge le certificat de preuve'),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
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
        description=_('Reçoit les notifications webhook Goodflag'),
    )
    def webhook(self, request):
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

        event_id = payload.get('id', '')
        event_type = payload.get('eventType', '')
        workflow_id = payload.get('workflowId', '')

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

        raw_status = ''
        normalized_status = ''
        if workflow_id:
            try:
                client = self._get_client()
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

                wf_data = client.get_workflow(workflow_id)
                raw_status = wf_data.get('status', '')
                normalized_status = wf_data.get('normalized_status', '')
            except GoodflagError as exc:
                logger.warning("Webhook re-validation failed: %s", exc)
                raw_status = 'unverified'
                normalized_status = 'error'

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

        if workflow_id and normalized_status:
            GoodflagWorkflowTrace.objects.filter(
                resource=self,
                goodflag_workflow_id=workflow_id,
            ).update(
                status=normalized_status,
                updated_at=timezone.now(),
            )

        if event_type in self._NOTIFY_EVENT_TYPES:
            self._notify_wcs(workflow_id, event_type, normalized_status, event_id)

        return JsonResponse({'status': 'ok'})

    @endpoint(
        name='retrieve-by-external-ref',
        perm='can_access',
        methods=['get'],
        description=_('Retrouve un workflow par référence externe Publik'),
        parameters={
            'external_ref': {'description': _('Référence externe'), 'example_value': 'DEM-2024-001'},
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
        description=_('Renvoie une invitation par email'),
        parameters={
            'workflow_id': {'description': _('ID du workflow'), 'example_value': 'wfl_abc123'},
            'external_ref': {'description': _('Référence externe Publik')},
            'recipient_email': {'description': _('Email du destinataire')},
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
        description=_('Liste et recherche les workflows'),
        parameters={
            'text': {'description': _('Texte de recherche')},
            'status': {'description': _('Filtre par statut')},
            'page': {'description': _('Index de page (défaut 0)')},
            'per_page': {'description': _('Éléments par page (défaut 50, max 100)')},
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


class GoodflagWorkflowTrace(models.Model):
    """Corrélation workflow Goodflag <-> demande Publik."""

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
    """Journal des événements webhook reçus de Goodflag."""

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
    """Métadonnées des documents uploadés ou signés."""

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
