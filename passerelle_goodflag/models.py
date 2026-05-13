import base64
import hmac
import io
import ipaddress
import json
import logging
import zipfile
from urllib.parse import unquote, urlparse

from django.db import models
from django.http import JsonResponse, StreamingHttpResponse
from django.utils.translation import gettext_lazy as _

from passerelle.base.models import BaseResource
from passerelle.utils.api import endpoint

from .client import GoodflagClient
from .exceptions import GoodflagError, GoodflagValidationError

logger = logging.getLogger(__name__)

# Auth params injected in URL/body by Passerelle signed-request middleware
_PASSERELLE_AUTH_PARAMS = frozenset({'orig', 'algo', 'timestamp', 'nonce', 'signature'})
_MAX_RECIPIENTS = 100
MAX_B64_LEN = int(50 * 1024 * 1024 * 4 / 3) + 1024


def _get_param(payload, key, default=None):
    val = payload.get(key, default)
    if isinstance(val, list):
        val = val[0] if val else default
    if val == '' and default is not None:
        return default
    return val


def _validate_file_url(url):
    """Block SSRF: HTTPS only, reject private/loopback/link-local hosts."""
    if not url:
        raise GoodflagValidationError("file_url is required")
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise GoodflagValidationError(f"file_url scheme '{parsed.scheme}' not allowed (https only)")
    hostname = (parsed.hostname or '').lower()
    try:
        addr = ipaddress.ip_address(hostname)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            raise GoodflagValidationError(f"file_url points to a non-routable address: {hostname}")
    except ValueError:
        pass
    for pat in ('localhost', '127.', '0.0.0.0', '::1', '169.254.', 'metadata.google', 'metadata.internal'):
        if hostname.startswith(pat) or hostname == pat.rstrip('.'):
            raise GoodflagValidationError(f"file_url points to a local/internal address: {hostname}")


def _sniff_content_type(content, declared_type):
    if content[:4] == b'%PDF':
        return 'application/pdf'
    if content[:4] == b'PK\x03\x04':
        return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    if content[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    if content[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    return declared_type


def _validate_file_content(content, content_type):
    if not content:
        raise GoodflagValidationError("Le fichier est vide")
    is_pdf_content = content.startswith(b'%PDF')
    is_pdf_type = 'pdf' in content_type.lower()
    if is_pdf_content or is_pdf_type:
        if is_pdf_type and not is_pdf_content:
            raise GoodflagValidationError(
                "Le fichier n'est pas un PDF valide (signature %PDF manquante)."
            )
        if b'/Encrypt' in content[:2048] + content[-512:]:
            raise GoodflagValidationError("Le PDF est protégé par chiffrement, Goodflag ne peut pas le signer.")
        return
    if 'wordprocessingml' in content_type or 'docx' in content_type.lower():
        if not content.startswith(b'PK\x03\x04'):
            raise GoodflagValidationError("Le fichier DOCX n'est pas valide (signature ZIP manquante).")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                if 'word/document.xml' not in zf.namelist():
                    raise GoodflagValidationError("Le fichier DOCX est corrompu (word/document.xml manquant).")
        except zipfile.BadZipFile:
            raise GoodflagValidationError("Le fichier DOCX est corrompu (archive ZIP invalide).")


def _parse_recipients(payload):
    """Parse recipients from the indexed form-encoded format (recipients_N_email)."""
    recipients = []
    for i in range(_MAX_RECIPIENTS):
        email = _get_param(payload, f'recipients_{i}_email')
        if not email:
            break
        recipient = {
            'email': email,
            'firstName': _get_param(payload, f'recipients_{i}_firstname', ''),
            'lastName': _get_param(payload, f'recipients_{i}_lastname', ''),
            'phone': _get_param(payload, f'recipients_{i}_phone', ''),
        }
        consent = _get_param(payload, f'recipients_{i}_consent_page_id')
        if consent:
            recipient['consentPageId'] = consent
        recipients.append(recipient)
    return recipients


def _build_workflow_payload(payload, resource):
    """Build the dict passed to client.create_workflow from a request payload."""
    name = _get_param(payload, 'name')
    if not name:
        raise GoodflagValidationError("'name' is required")
    if not resource.user_id:
        raise GoodflagValidationError("Configuration error: 'user_id' is missing in the connector settings.")

    steps_config = payload.get('steps')
    recipients = payload.get('recipients')
    if steps_config and recipients:
        raise GoodflagValidationError("'steps' and 'recipients' are mutually exclusive.")

    if not steps_config and not recipients:
        recipients = _parse_recipients(payload)
    if not steps_config and not recipients:
        email = _get_param(payload, 'recipient_email')
        if email:
            recipients = [{
                'email': email,
                'firstName': _get_param(payload, 'recipient_firstname', ''),
                'lastName': _get_param(payload, 'recipient_lastname', ''),
                'phone': _get_param(payload, 'recipient_phone', ''),
            }]
    if not steps_config and not recipients:
        raise GoodflagValidationError("'steps' or 'recipients' is required")

    default_consent = resource.default_consent_page_id
    if steps_config:
        steps = steps_config
        for step in steps:
            for r in step.get('recipients', []):
                if not r.get('consentPageId') and default_consent:
                    r['consentPageId'] = default_consent
    else:
        built = []
        for r in recipients:
            recipient = dict(r)
            if not recipient.get('consentPageId') and default_consent:
                recipient['consentPageId'] = default_consent
            if 'consentPageId' in recipient and not recipient['consentPageId']:
                del recipient['consentPageId']
            phone = recipient.pop('phone', None)
            if phone:
                recipient['phoneNumber'] = phone
            built.append(recipient)
        steps = [{'stepType': 'signature', 'recipients': built, 'maxInvites': 5}]

    return {
        'name': name,
        'steps': steps,
        'description': payload.get('description', ''),
        'workflow_mode': _get_param(payload, 'workflow_mode', 'FULL'),
        'layout_id': _get_param(payload, 'layout_id') or resource.default_layout_id,
        'metadata': payload.get('metadata', {}),
    }


def _extract_file(payload, request, passerelle_session):
    """Extract file content from payload — supports file dict, multipart, base64 or URL."""
    file_obj = payload.get('file')
    if isinstance(file_obj, str) and file_obj.startswith('{'):
        try:
            file_obj = json.loads(file_obj)
        except (ValueError, TypeError):
            pass

    filename = _get_param(payload, 'filename')
    content_type = _get_param(payload, 'content_type', 'application/pdf')
    content = None
    file_url = None

    if isinstance(file_obj, dict):
        b64 = file_obj.get('content')
        if not b64:
            raise GoodflagValidationError("'content' is missing in 'file' object")
        if len(b64) > MAX_B64_LEN:
            raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
        content = base64.b64decode(b64)
        filename = filename or file_obj.get('filename')
        content_type = file_obj.get('content_type') or content_type
    elif request.FILES.get('file'):
        f = request.FILES['file']
        content = f.read()
        filename = filename or f.name
    elif _get_param(payload, 'file_base64'):
        b64 = _get_param(payload, 'file_base64')
        if len(b64) > MAX_B64_LEN:
            raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
        content = base64.b64decode(b64)
    elif _get_param(payload, 'file_url'):
        file_url = _get_param(payload, 'file_url')
        _validate_file_url(file_url)
        resp = passerelle_session.get(file_url)
        if resp.status_code != 200:
            raise GoodflagError(f"Failed to fetch file from URL: HTTP {resp.status_code}")
        content = resp.content
        content_type = _sniff_content_type(content, content_type)

    if not content:
        raise GoodflagValidationError("'file', 'file_base64' or 'file_url' is required")

    _validate_file_content(content, content_type)
    if not filename and file_url:
        filename = unquote(urlparse(file_url).path.rstrip('/').rsplit('/', 1)[-1])
    return content, filename or 'document.pdf', content_type


def _download_response(result):
    response = StreamingHttpResponse(
        result['response'].iter_content(chunk_size=8192),
        content_type=result['content_type'],
    )
    response['Content-Disposition'] = f'attachment; filename="{result["filename"]}"'
    return response


class GoodflagResource(BaseResource):
    base_url = models.URLField(
        _('URL de base de l\'API Goodflag'), max_length=512,
        help_text=_('Ex: https://sgs-demo-test01.sunnystamp.com/api'),
    )
    access_token = models.CharField(
        _('Token d\'accès API'), max_length=512,
        help_text=_('Bearer token (format: act_xxx.yyy)'),
    )
    user_id = models.CharField(
        _('Identifiant utilisateur API'), max_length=256,
        help_text=_('Utilisateur Goodflag propriétaire des workflows (format: usr_xxx)'),
    )
    timeout = models.PositiveIntegerField(
        _('Timeout HTTP (secondes)'), default=30,
    )
    verify_ssl = models.BooleanField(
        _('Vérifier le certificat SSL'), default=True,
    )
    default_consent_page_id = models.CharField(
        _('ID de page de consentement par défaut'), max_length=256, blank=True, default='',
        help_text=_('Format: cop_xxx'),
    )
    default_signature_profile_id = models.CharField(
        _('ID de profil de signature par défaut'), max_length=256, blank=True, default='',
        help_text=_('Format: sip_xxx'),
    )
    default_layout_id = models.CharField(
        _('ID de layout par défaut'), max_length=256, blank=True, default='',
        help_text=_('Format: lay_xxx, requis si vous utilisez des métadonnées'),
    )
    webhook_secret = models.CharField(
        _('Secret du webhook'), max_length=256, blank=True, default='',
        help_text=_('Token de validation passé en query string par Goodflag (?token=...).'),
    )

    category = _('Connecteurs métiers')

    class Meta:
        verbose_name = _('Connecteur Goodflag (signature électronique)')
        verbose_name_plural = _('Connecteurs Goodflag (signature électronique)')

    # -- Helpers ----------------------------------------------------------

    def _parse_payload(self, request, **kwargs):
        content_type = request.content_type or ''
        body = request.body
        payload = {}

        for k, v in request.GET.lists():
            if k not in _PASSERELLE_AUTH_PARAMS:
                payload[k] = v[0] if len(v) == 1 else v

        if 'application/json' in content_type:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({k: v for k, v in body_data.items()
                                    if k not in _PASSERELLE_AUTH_PARAMS})
            except (ValueError, TypeError):
                if not payload:
                    raise GoodflagValidationError("Invalid JSON body")
        elif request.POST:
            for k, v in request.POST.lists():
                if k not in _PASSERELLE_AUTH_PARAMS:
                    payload[k] = v[0] if len(v) == 1 else v
        elif body:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    payload.update({k: v for k, v in body_data.items()
                                    if k not in _PASSERELLE_AUTH_PARAMS})
            except (ValueError, TypeError):
                pass

        if kwargs:
            payload.update({k: v for k, v in kwargs.items() if v is not None})

        return payload

    def _get_client(self):
        return GoodflagClient(
            base_url=self.base_url,
            access_token=self.access_token,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )

    def _resolve_workflow_id(self, payload):
        """Resolve workflow_id, optionally from external_ref via Goodflag search API."""
        workflow_id = _get_param(payload, 'workflow_id')
        if workflow_id:
            return workflow_id
        external_ref = (_get_param(payload, 'external_ref')
                        or _get_param(payload, 'display_id')
                        or _get_param(payload, 'uuid'))
        if not external_ref:
            return None
        client = self._get_client()
        try:
            search = client.search_workflows(text=external_ref)
        except GoodflagError as exc:
            logger.warning("Resolving external_ref=%s failed: %s", external_ref, exc)
            return None
        for wf in search.get('items', []):
            if any(wf.get(f'data{i}') == external_ref for i in range(1, 17)):
                return wf.get('id')
            if external_ref in (wf.get('name') or ''):
                return wf.get('id')
        return None

    def check_status(self):
        result = self._get_client().test_connection()
        if result.get('status') != 'ok':
            raise GoodflagError(result.get('message', 'Goodflag API unreachable'))

    # -- Endpoints --------------------------------------------------------

    @endpoint(
        name='create-workflow', perm='can_access', methods=['post'],
        description=_('Crée un workflow de signature Goodflag (statut draft, sans document).'),
    )
    def create_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        wf = _build_workflow_payload(payload, self)
        result = self._get_client().create_workflow(
            user_id=self.user_id, name=wf['name'], steps=wf['steps'],
            description=wf['description'], workflow_mode=wf['workflow_mode'],
            layout_id=wf['layout_id'], metadata=wf['metadata'],
        )
        if not result.get('workflow_id'):
            raise GoodflagError("Goodflag API failed to return a workflow ID.")
        return {'data': {'workflow_id': result['workflow_id'], 'status': result['status']}}

    @endpoint(
        name='submit-workflow', perm='can_access', methods=['post'],
        description=_('Crée, uploade le document et démarre un workflow en un seul appel.'),
    )
    def submit_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        wf = _build_workflow_payload(payload, self)
        client = self._get_client()

        create_result = client.create_workflow(
            user_id=self.user_id, name=wf['name'], steps=wf['steps'],
            description=wf['description'], workflow_mode=wf['workflow_mode'],
            layout_id=wf['layout_id'], metadata=wf['metadata'],
        )
        workflow_id = create_result.get('workflow_id')
        if not workflow_id:
            raise GoodflagError("Goodflag API failed to return a workflow ID.")

        signature_profile_id = (_get_param(payload, 'signature_profile_id')
                                or self.default_signature_profile_id)
        file_content, filename, content_type = _extract_file(payload, request, self.requests)
        upload_result = client.upload_document(
            workflow_id=workflow_id, file_content=file_content, filename=filename,
            content_type=content_type, signature_profile_id=signature_profile_id or None,
        )
        start_result = client.patch_workflow_status(workflow_id, 'started')
        return {'data': {
            'workflow_id': workflow_id,
            'status': start_result.get('status', 'started'),
            'document_id': upload_result.get('document_id', ''),
        }}

    @endpoint(
        name='upload-document', perm='can_access', methods=['post'],
        description=_('Upload un document dans un workflow Goodflag existant.'),
    )
    def upload_document(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        signature_profile_id = (_get_param(payload, 'signature_profile_id')
                                or self.default_signature_profile_id)
        file_content, filename, content_type = _extract_file(payload, request, self.requests)
        result = self._get_client().upload_document(
            workflow_id=workflow_id, file_content=file_content, filename=filename,
            content_type=content_type, signature_profile_id=signature_profile_id or None,
        )
        return {'data': result}

    @endpoint(
        name='start-workflow', perm='can_access', methods=['post'],
        description=_('Démarre un workflow Goodflag (envoie les invitations).'),
    )
    def start_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        result = self._get_client().patch_workflow_status(workflow_id, 'started')
        return {'data': result}

    @endpoint(
        name='stop-workflow', perm='can_access', methods=['post'],
        description=_('Arrête un workflow Goodflag.'),
    )
    def stop_workflow(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(self._parse_payload(request))
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        result = self._get_client().patch_workflow_status(workflow_id, 'stopped')
        return {'data': result}

    @endpoint(
        name='get-workflow', perm='can_access', methods=['get'],
        description=_('Récupère le détail d\'un workflow Goodflag.'),
    )
    def get_workflow(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        return {'data': self._get_client().get_workflow(workflow_id)}

    @endpoint(
        name='sync-status', perm='can_access', methods=['get'],
        description=_('Statut normalisé d\'un workflow (draft, started, finished, refused, error).'),
    )
    def sync_status(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        result = self._get_client().get_workflow(workflow_id)
        normalized = result.get('normalized_status', 'error')
        return {'data': {
            'workflow_id': workflow_id,
            'raw_status': result.get('status', ''),
            'status': normalized,
            'progress': result.get('progress', 0),
            'is_final': normalized in ('finished', 'refused'),
        }}

    @endpoint(
        name='create-invite', perm='can_access', methods=['post'],
        description=_('Crée une URL d\'invitation pour un destinataire d\'un workflow.'),
    )
    def create_invite(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._resolve_workflow_id(payload)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        email = _get_param(payload, 'recipient_email')
        if not email:
            raise GoodflagValidationError("'recipient_email' is required")
        result = self._get_client().create_invite(
            workflow_id, email,
            recipient_phone=_get_param(payload, 'recipient_phone'),
        )
        return {'data': result}

    @endpoint(
        name='download-signed-documents', perm='can_access', methods=['get'],
        description=_('Télécharge les documents signés d\'un workflow terminé.'),
    )
    def download_signed_documents(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        result = self._get_client().download(workflow_id, 'downloadDocuments', 'signed_documents')
        return _download_response(result)

    @endpoint(
        name='download-evidence', perm='can_access', methods=['get'],
        description=_('Télécharge le certificat de preuve d\'un workflow terminé.'),
    )
    def download_evidence(self, request, workflow_id=None, external_ref=None):
        if not workflow_id:
            workflow_id = self._resolve_workflow_id(request.GET)
        if not workflow_id:
            raise GoodflagValidationError("'workflow_id' or 'external_ref' is required")
        result = self._get_client().download(workflow_id, 'downloadEvidenceCertificate', 'evidence_certificate')
        return _download_response(result)

    @endpoint(
        name='webhook', perm='open', methods=['post'],
        description=_('Reçoit les notifications webhook de Goodflag.'),
    )
    def webhook(self, request):
        """
        Sécurité :
        - Goodflag ne signe pas ses webhooks (pas de HMAC).
        - Si webhook_secret est configuré, on valide le token URL.
        - Sinon, on re-valide auprès de l'API webhookEvents de Goodflag.
        """
        if self.webhook_secret:
            provided = request.GET.get('token', '')
            if not hmac.compare_digest(provided, self.webhook_secret):
                return JsonResponse({'error': 'Invalid token'}, status=403)

        try:
            payload = json.loads(request.body)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        event_id = payload.get('id', '')
        workflow_id = payload.get('workflowId') or payload.get('workflow_id', '')
        if not event_id:
            return JsonResponse({'error': 'Missing event id'}, status=400)

        if not self.webhook_secret and event_id and workflow_id:
            try:
                verified = self._get_client().get_webhook_event(event_id)
                if verified.get('workflowId') != workflow_id:
                    return JsonResponse({'error': 'Event verification failed'}, status=403)
            except GoodflagError as exc:
                logger.warning("Webhook revalidation failed for %s: %s", event_id, exc)
                return JsonResponse({'error': 'Revalidation failed'}, status=403)

        return JsonResponse({'status': 'ok'}, status=200)

    @endpoint(
        name='retrieve-by-external-ref', perm='can_access', methods=['get'],
        description=_('Retrouve les workflows associés à une référence externe Publik via l\'API Goodflag.'),
    )
    def retrieve_by_external_ref(self, request, external_ref):
        if not external_ref:
            raise GoodflagValidationError("'external_ref' is required")
        client = self._get_client()
        search = client.search_workflows(text=external_ref)
        results = []
        for wf in search.get('items', []):
            match = any(wf.get(f'data{i}') == external_ref for i in range(1, 17))
            if match or external_ref in (wf.get('name') or ''):
                results.append({
                    'workflow_id': wf.get('id', ''),
                    'workflow_name': wf.get('name', ''),
                    'external_ref': external_ref,
                    'status': wf.get('workflowStatus', ''),
                })
        return {'data': {'count': len(results), 'results': results}}
