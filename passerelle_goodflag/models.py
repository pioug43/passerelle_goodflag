import base64
import io
import ipaddress
import json
import zipfile
from urllib.parse import unquote, urlparse

from django import forms
from django.db import models
from django.http import StreamingHttpResponse
from django.utils.translation import gettext_lazy as _

from passerelle.base.models import BaseResource
from passerelle.utils.api import endpoint
from passerelle.utils.jsonresponse import APIError

from .client import (
    MAX_B64_LEN, MAX_RECIPIENTS, MAX_UPLOAD_SIZE,
    FILE_URL_CHUNK, FILE_URL_TIMEOUT,
    GoodflagClient,
)

_PASSERELLE_AUTH_PARAMS = frozenset({'orig', 'algo', 'timestamp', 'nonce', 'signature'})


def _get_param(payload, key, default=None):
    val = payload.get(key, default)
    if isinstance(val, list):
        val = val[0] if val else default
    if val == '' and default is not None:
        return default
    return val


def _parse_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _validate_file_url(url):
    if not url:
        raise APIError("file_url is required", http_status=400)
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise APIError(f"file_url scheme '{parsed.scheme}' not allowed (https only)", http_status=400)
    hostname = (parsed.hostname or '').lower()
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise APIError(f"file_url points to a non-routable address: {hostname}", http_status=400)
    except ValueError:
        pass
    for pat in ('localhost', '127.', '0.0.0.0', '::1', '169.254.', 'metadata.google', 'metadata.internal'):
        if hostname.startswith(pat) or hostname == pat.rstrip('.'):
            raise APIError(f"file_url points to a local/internal address: {hostname}", http_status=400)


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
        raise APIError("Le fichier est vide", http_status=400)
    is_pdf_content = content.startswith(b'%PDF')
    is_pdf_type = 'pdf' in content_type.lower()
    if is_pdf_content or is_pdf_type:
        if is_pdf_type and not is_pdf_content:
            raise APIError("Le fichier n'est pas un PDF valide (signature %PDF manquante).", http_status=400)
        if b'/Encrypt' in content[:2048] + content[-512:]:
            raise APIError("Le PDF est protégé par chiffrement, Goodflag ne peut pas le signer.", http_status=400)
        return
    if 'wordprocessingml' in content_type or 'docx' in content_type.lower():
        if not content.startswith(b'PK\x03\x04'):
            raise APIError("Le fichier DOCX n'est pas valide (signature ZIP manquante).", http_status=400)
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                if 'word/document.xml' not in zf.namelist():
                    raise APIError("Le fichier DOCX est corrompu (word/document.xml manquant).", http_status=400)
        except zipfile.BadZipFile:
            raise APIError("Le fichier DOCX est corrompu (archive ZIP invalide).", http_status=400)


def _parse_recipients(payload):
    recipients = []
    for i in range(MAX_RECIPIENTS):
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
    name = _get_param(payload, 'name')
    if not name:
        raise APIError("'name' is required", http_status=400)
    if not resource.user_id:
        raise APIError("Configuration error: 'user_id' is missing in the connector settings.", http_status=500)

    steps_config = payload.get('steps')
    if isinstance(steps_config, str):
        try:
            steps_config = json.loads(steps_config)
        except (ValueError, TypeError):
            raise APIError("'steps' must be valid JSON", http_status=400)
    recipients = payload.get('recipients')
    if isinstance(recipients, str):
        try:
            recipients = json.loads(recipients)
        except (ValueError, TypeError):
            raise APIError("'recipients' must be valid JSON", http_status=400)
    if steps_config and recipients:
        raise APIError("'steps' and 'recipients' are mutually exclusive.", http_status=400)

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
        raise APIError("'steps' or 'recipients' is required", http_status=400)

    default_consent = resource.default_consent_page_id
    if steps_config:
        steps = steps_config
        for step in steps:
            for r in step.get('recipients', []):
                if not r.get('consentPageId') and default_consent:
                    r['consentPageId'] = default_consent
                for empty_key in [k for k, v in list(r.items()) if v in (None, '', '{{ }}')]:
                    del r[empty_key]
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


def _extract_file(payload, request, session):
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
            raise APIError("'content' is missing in 'file' object", http_status=400)
        if len(b64) > MAX_B64_LEN:
            raise APIError("File content exceeds maximum allowed size (50 MB)", http_status=400)
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
            raise APIError("File content exceeds maximum allowed size (50 MB)", http_status=400)
        content = base64.b64decode(b64)
    elif _get_param(payload, 'file_url'):
        file_url = _get_param(payload, 'file_url')
        _validate_file_url(file_url)
        resp = session.get(file_url, stream=True, timeout=FILE_URL_TIMEOUT)
        if resp.status_code != 200:
            resp.close()
            raise APIError(f"Failed to fetch file from URL: HTTP {resp.status_code}", http_status=502)
        buf = bytearray()
        try:
            for chunk in resp.iter_content(chunk_size=FILE_URL_CHUNK):
                if not chunk:
                    continue
                buf.extend(chunk)
                if len(buf) > MAX_UPLOAD_SIZE:
                    raise APIError(
                        f"File at file_url exceeds maximum allowed size ({MAX_UPLOAD_SIZE} bytes)",
                        http_status=400,
                    )
        finally:
            resp.close()
        content = buf
        content_type = _sniff_content_type(content, content_type)

    if not content:
        raise APIError("'file', 'file_base64' or 'file_url' is required", http_status=400)

    _validate_file_content(content, content_type)
    if not filename and file_url:
        filename = unquote(urlparse(file_url).path.rstrip('/').rsplit('/', 1)[-1])
    return content, filename or 'document.pdf', content_type


def _download_response(result):
    resp = result['response']
    streaming = StreamingHttpResponse(
        resp.iter_content(chunk_size=8192),
        content_type=result['content_type'],
    )
    from .client import _sanitize_filename
    safe_name = _sanitize_filename(result['filename'])
    streaming['Content-Disposition'] = f'attachment; filename="{safe_name}"'
    return streaming


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

    category = _('Connecteurs métiers')

    class Meta:
        verbose_name = _('Connecteur Goodflag (signature électronique)')
        verbose_name_plural = _('Connecteurs Goodflag (signature électronique)')

    @staticmethod
    def get_form_class():
        from django.forms import ModelForm

        class Form(ModelForm):
            access_token = forms.CharField(widget=forms.PasswordInput(render_value=True), required=True)

            class Meta:
                model = GoodflagResource
                fields = '__all__'

        return Form

    def _parse_payload(self, request, **kwargs):
        payload = {}

        def _merge_multivalued(items):
            for key, values in items:
                if key in _PASSERELLE_AUTH_PARAMS:
                    continue
                payload[key] = values[0] if len(values) == 1 else values

        def _merge_dict(data):
            payload.update({k: v for k, v in data.items() if k not in _PASSERELLE_AUTH_PARAMS})

        _merge_multivalued(request.GET.lists())
        content_type = request.content_type or ''
        body = request.body
        if 'application/json' in content_type:
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                if not payload:
                    raise APIError("Invalid JSON body", http_status=400)
                data = None
            if isinstance(data, dict):
                _merge_dict(data)
        elif request.POST:
            _merge_multivalued(request.POST.lists())
        elif body:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    _merge_dict(data)
            except (ValueError, TypeError):
                pass
        payload.update({k: v for k, v in kwargs.items() if v is not None})
        return payload

    def make_requests_auth(self, session):
        from requests.auth import AuthBase
        from urllib.parse import urlparse

        resource = self

        class BearerAuth(AuthBase):
            def __call__(self, r):
                if urlparse(r.url).netloc == urlparse(resource.base_url).netloc:
                    r.headers['Authorization'] = f'Bearer {resource.access_token}'
                    r.headers['Accept'] = 'application/json'
                return r

        return BearerAuth()

    def _get_client(self):
        return GoodflagClient(
            session=self.requests,
            base_url=self.base_url,
            user_id=self.user_id,
            timeout=self.timeout,
        )

    def _resolve_workflow_id(self, payload):
        workflow_id = _get_param(payload, 'workflow_id')
        if workflow_id:
            return workflow_id
        external_ref = (_get_param(payload, 'external_ref')
                        or _get_param(payload, 'display_id')
                        or _get_param(payload, 'uuid'))
        if not external_ref:
            return None
        try:
            search = self._get_client().search_workflows(text=external_ref, cache_duration=10)
        except APIError:
            self.logger.warning("Resolving external_ref=%s failed", external_ref)
            return None
        for wf in search.get('items', []):
            if any(wf.get(f'data{i}') == external_ref for i in range(1, 17)):
                return wf.get('id')
        return None

    def _require_workflow_id(self, payload):
        workflow_id = self._resolve_workflow_id(payload)
        if workflow_id:
            return workflow_id
        external_ref = (_get_param(payload, 'external_ref')
                        or _get_param(payload, 'display_id')
                        or _get_param(payload, 'uuid'))
        if external_ref:
            raise APIError(f"No Goodflag workflow found for external_ref={external_ref!r}", http_status=404)
        raise APIError("'workflow_id' or 'external_ref' is required", http_status=400)

    def check_status(self):
        self._get_client().test_connection()

    # -- Endpoints --------------------------------------------------------

    @endpoint(
        name='create-workflow', perm='can_access', methods=['post'],
        description=_('Crée un workflow de signature Goodflag (statut draft, sans document).'),
        long_description=_(
            'Exemple requête JSON :\n'
            '{"name": "Convention de stage 2026-001", '
            '"recipient_email": "signataire@example.com", '
            '"recipient_firstname": "Jean", "recipient_lastname": "Dupont", '
            '"recipient_phone": "+33612345678"}\n\n'
            'Réponse :\n'
            '{"data": {"workflow_id": "wfl_K49wUU...", "status": "draft"}}'
        ),
        parameters={
            'name': {'description': 'Nom/objet du workflow (obligatoire)', 'example_value': 'Convention de stage 2026-001'},
            'recipient_email': {'description': 'Email du signataire (format simple)', 'example_value': 'signataire@example.com'},
            'recipient_firstname': {'description': 'Prénom du signataire', 'example_value': 'Jean'},
            'recipient_lastname': {'description': 'Nom du signataire', 'example_value': 'Dupont'},
            'recipient_phone': {'description': 'Téléphone pour OTP SMS (format international)', 'example_value': '+33612345678'},
            'workflow_mode': {'description': 'Mode du workflow : FULL (défaut) ou LIGHT', 'example_value': 'FULL'},
            'description': {'description': 'Description libre du workflow'},
            'external_ref': {'description': 'Référence externe (ex: numéro de demande Publik)', 'example_value': '81-1'},
        },
    )
    def create_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        wf = _build_workflow_payload(payload, self)
        result = self._get_client().create_workflow(
            name=wf['name'], steps=wf['steps'],
            description=wf['description'], workflow_mode=wf['workflow_mode'],
            layout_id=wf['layout_id'], metadata=wf['metadata'],
        )
        if not result.get('workflow_id'):
            raise APIError("Goodflag API failed to return a workflow ID.", http_status=502)
        return {'data': {'workflow_id': result['workflow_id'], 'status': result['status']}}

    @endpoint(
        name='submit-workflow', perm='can_access', methods=['post'],
        description=_('Crée + uploade + démarre un workflow en un seul appel (PDF/DOCX/image).'
            'et démarre les invitations.'),
        long_description=_(
'Exemple requête JSON :\n'
            '{"name": "Convention de stage 2026", '
            '"recipient_email": "signataire@example.com", '
            '"recipient_firstname": "Jean", "recipient_lastname": "Dupont", '
            '"recipient_phone": "+33612345678", '
            '"file_url": "https://formulaires.example.com/demande/42/download?f=2", '
            '"content_type": "application/pdf", '
            '"external_ref": "81-1"}\n\n'
            'Exemple avec DOCX :\n'
            '{"name": "Contrat", "recipient_email": "...", '
            '"file_url": "https://.../download?f=3", '
            '"content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}\n\n'
            'Exemple multi-signataires :\n'
            '{"name": "Convention tripartite", '
            '"recipients_0_email": "alice@example.com", "recipients_0_firstname": "Alice", '
            '"recipients_0_phone": "+33611111111", '
            '"recipients_1_email": "bob@example.com", "recipients_1_firstname": "Bob", '
            '"recipients_1_phone": "+33622222222", '
            '"file_url": "https://.../download?f=2"}\n\n'
            'Réponse :\n'
            '{"data": {"workflow_id": "wfl_CpW8YQ...", "status": "started", "document_id": "doc_2Z1HFN..."}}'
        ),
        parameters={
            'name': {'description': 'Nom/objet du workflow (obligatoire)', 'example_value': 'Convention de stage 2026'},
            'recipient_email': {'description': 'Email du signataire', 'example_value': 'signataire@example.com'},
            'recipient_firstname': {'description': 'Prénom du signataire', 'example_value': 'Jean'},
            'recipient_lastname': {'description': 'Nom du signataire', 'example_value': 'Dupont'},
            'recipient_phone': {'description': 'Téléphone pour OTP SMS', 'example_value': '+33612345678'},
            'file_url': {'description': 'URL HTTPS du document (récupéré côté Passerelle)', 'example_value': 'https://formulaires.example.com/demande/42/download?f=2'},
            'file_base64': {'description': 'Document encodé en base64 (alternative à file_url)'},
            'filename': {'description': 'Nom du fichier', 'example_value': 'convention.pdf'},
            'content_type': {'description': 'Type MIME : application/pdf, DOCX, image/jpeg, image/png', 'example_value': 'application/pdf'},
            'signature_profile_id': {'description': 'Profil de signature (surcharge le défaut)', 'example_value': 'sip_xxx'},
            'external_ref': {'description': 'Référence externe Publik', 'example_value': '{{ form_number }}'},
        },
    )
    def submit_workflow(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        wf = _build_workflow_payload(payload, self)
        client = self._get_client()

        create_result = client.create_workflow(
            name=wf['name'], steps=wf['steps'],
            description=wf['description'], workflow_mode=wf['workflow_mode'],
            layout_id=wf['layout_id'], metadata=wf['metadata'],
        )
        workflow_id = create_result.get('workflow_id')
        if not workflow_id:
            raise APIError("Goodflag API failed to return a workflow ID.", http_status=502)

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
        description=_('Upload un document (PDF/DOCX/image, max 50 Mo) dans un workflow draft.'
            'Taille max : 50 Mo. Les DOCX sont convertis en PDF côté Goodflag.'),
        long_description=_(
'Exemple via file_url :\n'
            '{"workflow_id": "wfl_xxx", '
            '"file_url": "https://formulaires.example.com/demande/42/download?f=2", '
            '"filename": "convention.pdf", "content_type": "application/pdf"}\n\n'
            'Exemple via base64 :\n'
            '{"workflow_id": "wfl_xxx", "file_base64": "<base64>", '
            '"filename": "contrat.docx", '
            '"content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}\n\n'
            'Réponse :\n'
            '{"data": {"workflow_id": "wfl_xxx", "document_id": "doc_xxx", "filename": "convention.pdf"}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag (ou external_ref)', 'example_value': 'wfl_xxx'},
            'file_url': {'description': 'URL HTTPS du document Publik', 'example_value': 'https://formulaires.example.com/demande/42/download?f=2'},
            'file_base64': {'description': 'Document encodé en base64 (alternative à file_url)'},
            'filename': {'description': 'Nom du fichier', 'example_value': 'document.pdf'},
            'content_type': {'description': 'Type MIME du document', 'example_value': 'application/pdf'},
            'signature_profile_id': {'description': 'Profil de signature (surcharge le défaut)', 'example_value': 'sip_xxx'},
        },
    )
    def upload_document(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._require_workflow_id(payload)
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
        description=_('Démarre un workflow en draft → envoie les invitations email aux signataires.'),
        long_description=_(
'Exemple : {"workflow_id": "wfl_xxx"}\n\n'
            'Réponse : {"data": {"workflow_id": "wfl_xxx", "status": "started"}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag', 'example_value': 'wfl_xxx'},
            'external_ref': {'description': 'Ou référence externe (alternative à workflow_id)', 'example_value': '81-1'},
        },
    )
    def start_workflow(self, request, **kwargs):
        workflow_id = self._require_workflow_id(self._parse_payload(request, **kwargs))
        return {'data': self._get_client().patch_workflow_status(workflow_id, 'started')}

    @endpoint(
        name='stop-workflow', perm='can_access', methods=['post'],
        description=_('Arrête un workflow en cours (statut → refused).'
            'Les invitations en attente sont annulées.'),
        long_description=_(
'Exemple : {"workflow_id": "wfl_xxx"}\n\n'
            'Réponse : {"data": {"workflow_id": "wfl_xxx", "status": "stopped"}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag', 'example_value': 'wfl_xxx'},
            'external_ref': {'description': 'Ou référence externe', 'example_value': '81-1'},
        },
    )
    def stop_workflow(self, request, **kwargs):
        workflow_id = self._require_workflow_id(self._parse_payload(request, **kwargs))
        return {'data': self._get_client().patch_workflow_status(workflow_id, 'stopped')}

    @endpoint(
        name='resend-invite', perm='can_access', methods=['post'],
        description=_('Renvoie une invitation par email à un destinataire (relance). '
            'Utile si le signataire n\'a pas reçu ou a perdu l\'email initial.'),
        long_description=_(
'Exemple : {"workflow_id": "wfl_xxx", "recipient_email": "signataire@example.com"}\n\n'
            'Réponse : {"data": {"invite_url": "https://...", "workflow_id": "wfl_xxx"}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag', 'example_value': 'wfl_xxx'},
            'recipient_email': {'description': 'Email du destinataire à relancer (obligatoire)', 'example_value': 'signataire@example.com'},
        },
    )
    def resend_invite(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        workflow_id = self._require_workflow_id(payload)
        email = _get_param(payload, 'recipient_email')
        if not email:
            raise APIError("'recipient_email' is required", http_status=400)
        return {'data': self._get_client().send_invite(workflow_id, email)}

    @endpoint(
        name='sync-status', perm='can_access', methods=['get'],
        description=_('Statut normalisé pour polling WCS (cache 10s).'),
        # was: description=_('

        long_description=_(
'Exemple appel : ?workflow_id=wfl_xxx\n'
            'Ou via référence : ?external_ref=81-1\n\n'
            'Réponse (en cours) :\n'
            '{"data": {"workflow_id": "wfl_xxx", "raw_status": "started", '
            '"status": "started", "progress": 50, "is_final": false}}\n\n'
            'Réponse (terminé) :\n'
            '{"data": {"workflow_id": "wfl_xxx", "raw_status": "finished", '
            '"status": "finished", "progress": 100, "is_final": true}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag', 'example_value': 'wfl_xxx'},
            'external_ref': {'description': 'Référence externe Publik (alternative à workflow_id)', 'example_value': '81-1'},
        },
    )
    def sync_status(self, request, **kwargs):
        workflow_id = self._require_workflow_id(self._parse_payload(request, **kwargs))
        result = self._get_client().get_workflow(workflow_id, cache_duration=10)
        normalized = result.get('normalized_status', 'error')
        return {'data': {
            'workflow_id': workflow_id,
            'raw_status': result.get('status', ''),
            'status': normalized,
            'progress': result.get('progress', 0),
            'is_final': normalized in ('finished', 'refused'),
        }}

    @endpoint(
        name='list-workflows', perm='can_access', methods=['get'],
        description=_('Liste et recherche les workflows Goodflag (pagination, tri par date décroissante). Cache 15s.'),
        long_description=_(
'Exemple : ?text=Convention&per_page=10\n\n'
            'Réponse :\n'
            '{"data": {"total": 42, "page": 0, "per_page": 10, "items": ['
            '{"workflow_id": "wfl_xxx", "name": "Convention stage", "status": "started", '
            '"progress": 50, "created": "2026-05-14T13:26:54Z"}]}}'
        ),
        parameters={
            'text': {'description': 'Recherche texte sur nom et métadonnées', 'example_value': 'Convention stage'},
            'page': {'description': 'Index de page (0-based, défaut: 0)', 'example_value': '0'},
            'per_page': {'description': 'Résultats par page (défaut: 50, max: 100)', 'example_value': '50'},
        },
    )
    def list_workflows(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        text = _get_param(payload, 'text') or None
        page_index = _parse_int(_get_param(payload, 'page'), default=0)
        items_per_page = min(_parse_int(_get_param(payload, 'per_page'), default=50), 100)
        result = self._get_client().search_workflows(
            text=text, items_per_page=items_per_page, page_index=page_index, cache_duration=15,
        )
        return {'data': {
            'total': result.get('totalItems', 0),
            'page': page_index,
            'per_page': items_per_page,
            'items': [{
                'workflow_id': wf.get('id'),
                'name': wf.get('name'),
                'status': wf.get('workflowStatus'),
                'progress': wf.get('progress', 0),
                'created': wf.get('created'),
                'updated': wf.get('updated'),
            } for wf in result.get('items', [])],
        }}

    @endpoint(
        name='get-workflow', perm='can_access', methods=['get'],
        description=_('Détail complet d\'un workflow : statut, étapes, destinataires, progression.'),
        long_description=_(
'Exemple : ?workflow_id=wfl_xxx\n\n'
            'Réponse :\n'
            '{"data": {"workflow_id": "wfl_xxx", "status": "started", '
            '"normalized_status": "started", "name": "Convention stage", '
            '"progress": 50, "steps": [{"stepType": "signature", "recipients": [...]}]}}'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag', 'example_value': 'wfl_xxx'},
            'external_ref': {'description': 'Ou référence externe Publik', 'example_value': '81-1'},
        },
    )
    def get_workflow(self, request, **kwargs):
        workflow_id = self._require_workflow_id(self._parse_payload(request, **kwargs))
        return {'data': self._get_client().get_workflow(workflow_id)}

    @endpoint(
        name='get-viewer-url', perm='can_access', methods=['get', 'post'],
        description=_('Génère une URL temporaire de visualisation d\'un document (lecture seule, pas de signature).'),
        long_description=_(
'Exemple : ?document_id=doc_xxx\n'
            'Avec retour : ?document_id=doc_xxx&redirect_url=https://formulaires.example.com/demande/42/\n\n'
            'Réponse :\n'
            '{"data": {"viewer_url": "https://goodflag.com/viewer/...", "document_id": "doc_xxx"}}'
        ),
        parameters={
            'document_id': {'description': 'ID du document Goodflag (obligatoire)', 'example_value': 'doc_xxx'},
            'redirect_url': {'description': 'URL de retour après fermeture du viewer', 'example_value': 'https://formulaires.example.com/demande/42/'},
            'expired': {'description': 'Date d\'expiration de l\'URL (ISO 8601)', 'example_value': '2026-12-31T23:59:59Z'},
        },
    )
    def get_viewer_url(self, request, **kwargs):
        payload = self._parse_payload(request, **kwargs)
        document_id = _get_param(payload, 'document_id')
        if not document_id:
            raise APIError("'document_id' is required", http_status=400)
        return {'data': self._get_client().get_document_viewer_url(
            document_id,
            redirect_url=_get_param(payload, 'redirect_url'),
            expired=_get_param(payload, 'expired'),
        )}

    @endpoint(
        name='download-signed-documents', perm='can_access', methods=['get'],
        description=_('Télécharge les documents signés d\'un workflow terminé (status=finished). '
            'Retourne un flux binaire PDF ou ZIP (si plusieurs documents).'),
        long_description=_(
'Exemple : ?workflow_id=wfl_xxx\n\n'
            'Réponse : flux binaire avec Content-Disposition: attachment; filename="signed_documents.pdf"\n'
            'Pas de wrapper JSON — le fichier est retourné directement.'
        ),
        parameters={
            'workflow_id': {'description': 'ID du workflow Goodflag (doit être terminé)', 'example_value': 'wfl_xxx'},
            'external_ref': {'description': 'Ou référence externe Publik', 'example_value': '81-1'},
        },
    )
    def download_signed_documents(self, request, **kwargs):
        workflow_id = self._require_workflow_id(self._parse_payload(request, **kwargs))
        return _download_response(self._get_client().download_signed_documents(workflow_id))
