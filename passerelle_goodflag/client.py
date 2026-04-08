"""
Client HTTP pour l'API Goodflag Workflow Manager (v1.19.4).

Centralise les appels HTTP, l'authentification Bearer, les retries
et le mapping d'erreurs vers les exceptions métier.
"""

import base64
import io
import logging
import re
from urllib.parse import unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import (
    GoodflagAuthError,
    GoodflagError,
    GoodflagNotFoundError,
    GoodflagRateLimitError,
    GoodflagTimeoutError,
    GoodflagUploadError,
    GoodflagValidationError,
)

logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 Mo

ALLOWED_CONTENT_TYPES = (
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/jpeg',
    'image/png',
    'image/webp',
)

# Mapping statuts Goodflag -> statuts normalisés Publik
STATUS_MAP = {
    'draft': 'draft',
    'started': 'started',
    'stopped': 'refused',
    'finished': 'finished',
    'archived': 'archived',
}

MAX_METADATA_SLOTS = 16


def _parse_content_disposition_filename(header, default):
    """Extrait le nom de fichier depuis un header Content-Disposition (RFC 6266)."""
    if not header:
        return default
    # RFC 5987 : filename*=charset''encoded_value (prioritaire)
    m = re.search(r"filename\*\s*=\s*[^']*''([^\s;]+)", header, re.IGNORECASE)
    if m:
        return unquote(m.group(1)) or default
    # RFC 2183 : filename="value"
    m = re.search(r'filename\s*=\s*"([^"]*)"', header, re.IGNORECASE)
    if m:
        return m.group(1) or default
    m = re.search(r'filename\s*=\s*([^\s;]+)', header, re.IGNORECASE)
    if m:
        return m.group(1).strip("'") or default
    return default


def _sanitize_for_log(data):
    """Supprime les secrets et données sensibles avant journalisation."""
    if not isinstance(data, dict):
        return data
    sanitized = dict(data)
    sensitive_keys = ('access_token', 'token', 'authorization', 'password', 'secret')
    for key in list(sanitized.keys()):
        if key.lower() in sensitive_keys:
            sanitized[key] = '***MASKED***'
        elif isinstance(sanitized[key], dict):
            sanitized[key] = _sanitize_for_log(sanitized[key])
        elif isinstance(sanitized[key], list):
            sanitized[key] = [
                _sanitize_for_log(item) if isinstance(item, dict) else item
                for item in sanitized[key]
            ]
    return sanitized


class GoodflagClient:
    """Client HTTP pour l'API Goodflag."""

    def __init__(self, base_url, access_token, timeout=30, verify_ssl=True):
        if not base_url:
            raise GoodflagValidationError("base_url is required")
        if not access_token:
            raise GoodflagValidationError("access_token is required")

        self.base_url = base_url.rstrip('/')
        self.access_token = access_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json',
        })
        self.session.verify = self.verify_ssl

        # Retry uniquement sur les méthodes idempotentes pour éviter
        # les doublons (création de workflow, démarrage, etc.)
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path):
        return f'{self.base_url}/{path.lstrip("/")}'

    def _request(self, method, path, json_data=None, params=None, files=None,
                 data=None, headers=None, raw_response=False):
        """Effectue une requête HTTP avec gestion centralisée des erreurs."""
        url = self._url(path)

        logger.debug(
            "Goodflag API call: %s %s params=%s",
            method, url, _sanitize_for_log(params)
        )

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
                files=files,
                data=data,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            raise GoodflagTimeoutError(
                f"Timeout after {self.timeout}s calling {method} {url}"
            )
        except requests.exceptions.ConnectionError as exc:
            raise GoodflagError(f"Connection error calling {method} {url}: {exc}")
        except requests.exceptions.RequestException as exc:
            raise GoodflagError(f"HTTP error calling {method} {url}: {exc}")

        if raw_response:
            if response.status_code >= 400:
                self._raise_for_status(response)
            return response

        return self._handle_response(response)

    def _handle_response(self, response):
        """Parse la réponse JSON et lève des exceptions métier si erreur."""
        if response.status_code >= 400:
            self._raise_for_status(response)

        if response.status_code == 204:
            return {}

        content_type = response.headers.get('Content-Type', '')
        if 'application/json' not in content_type:
            return {'raw_text': response.text}

        try:
            data = response.json()
        except ValueError:
            raise GoodflagError(
                f"Invalid JSON in response (HTTP {response.status_code})",
                status_code=response.status_code,
            )

        if isinstance(data, str):
            return {'version': data}

        return data

    def _raise_for_status(self, response):
        """Lève l'exception métier appropriée selon le code HTTP."""
        try:
            error_data = response.json()
        except ValueError:
            error_data = {'raw': response.text[:500]}

        error_msg = (
            error_data.get('message')
            or error_data.get('error')
            or str(error_data)
        )
        error_code = error_data.get('code', '')

        logger.warning(
            "Goodflag API error: HTTP %s - %s (code=%s)",
            response.status_code, error_msg, error_code
        )

        status = response.status_code
        url = response.url
        kwargs = dict(status_code=status, response_data=error_data)

        if status == 401:
            raise GoodflagAuthError(f"Authentication failed: {error_msg} (URL: {url})", **kwargs)
        if status == 403:
            raise GoodflagAuthError(f"Forbidden: {error_msg} (URL: {url})", **kwargs)
        if status == 404:
            raise GoodflagNotFoundError(f"Not found: {error_msg} (URL: {url})", **kwargs)
        if status in (400, 422):
            raise GoodflagValidationError(f"Validation error: {error_msg} (URL: {url})", **kwargs)
        if status == 429:
            try:
                retry_after = int(response.headers.get('Retry-After', 60))
            except (TypeError, ValueError):
                retry_after = 60
            raise GoodflagRateLimitError(
                f"Rate limit exceeded, retry after {retry_after}s (URL: {url})",
                retry_after=retry_after, **kwargs,
            )
        raise GoodflagError(f"API error (HTTP {status}): {error_msg} (URL: {url})", **kwargs)

    # -- Méthodes métier ---------------------------------------------------

    def test_connection(self):
        """Teste la connexion via GET /api/version."""
        try:
            data = self._request('GET', '/version')
            version = data.get('version', str(data))
            return {
                'status': 'ok',
                'message': 'Connection successful',
                'version': version,
            }
        except GoodflagAuthError:
            return {
                'status': 'error',
                'message': 'Authentication failed – check your access token',
            }
        except GoodflagError as exc:
            return {
                'status': 'error',
                'message': str(exc),
            }

    def create_workflow(self, user_id, name, steps,
                        description=None, workflow_mode=None,
                        notified_events=None, watchers=None,
                        template_id=None, allow_consolidation=None,
                        layout_id=None, metadata=None,
                        external_ref=None,
                        allowed_comanager_users=None,
                        comanager_notified_events=None):
        """
        Crée un workflow via POST /api/users/{userId}/workflows.

        Le workflow est créé en statut draft. Il faudra ensuite uploader
        un document puis le démarrer (ou utiliser submit-workflow).
        """
        payload = {
            'name': name,
            'steps': steps,
            'workflowMode': workflow_mode or 'FULL',
        }
        if description:
            payload['description'] = description
        if notified_events:
            payload['notifiedEvents'] = notified_events
        if watchers:
            payload['watchers'] = watchers
        if template_id:
            payload['templateId'] = template_id
        if allow_consolidation is not None:
            payload['allowConsolidation'] = allow_consolidation
        if layout_id:
            payload['layoutId'] = layout_id
        if allowed_comanager_users:
            payload['allowedCoManagerUsers'] = allowed_comanager_users
        if comanager_notified_events:
            payload['coManagerNotifiedEvents'] = comanager_notified_events

        # Champs data1-data16
        if metadata and isinstance(metadata, dict):
            for key, value in metadata.items():
                if key.startswith('data') and key[4:].isdigit():
                    slot_num = int(key[4:])
                    if 1 <= slot_num <= MAX_METADATA_SLOTS:
                        payload[key] = str(value)

        logger.info(
            "Creating Goodflag workflow: name=%s, user_id=%s, external_ref=%s",
            name, user_id, external_ref
        )

        data = self._request(
            'POST', f'/users/{user_id}/workflows', json_data=payload
        )

        workflow_id = data.get('id', '')
        status = data.get('workflowStatus', 'draft')

        logger.info(
            "Goodflag workflow created: workflow_id=%s, status=%s",
            workflow_id, status
        )

        return {
            'workflow_id': workflow_id,
            'status': status,
            'raw': data,
        }

    def upload_document(self, workflow_id, file_content, filename,
                        content_type='application/pdf',
                        signature_profile_id=None,
                        create_documents=True,
                        ignore_attachments=False):
        """
        Upload un document via POST /api/workflows/{id}/parts.

        Le fichier est envoyé en binaire brut avec Content-Disposition.
        """
        if content_type not in ALLOWED_CONTENT_TYPES:
            raise GoodflagValidationError(
                f"Content type '{content_type}' not allowed. "
                f"Allowed: {', '.join(ALLOWED_CONTENT_TYPES)}"
            )

        if isinstance(file_content, str):
            file_content = base64.b64decode(file_content)

        if len(file_content) > MAX_UPLOAD_SIZE:
            raise GoodflagValidationError(
                f"File too large ({len(file_content)} bytes). "
                f"Max: {MAX_UPLOAD_SIZE} bytes"
            )

        params = {
            'createDocuments': str(create_documents).lower(),
            'ignoreAttachments': str(ignore_attachments).lower(),
        }
        if signature_profile_id:
            params['signatureProfileId'] = signature_profile_id
        if content_type != 'application/pdf':
            params['convertToPdf'] = 'true'

        # Envoi en binaire brut (pas multipart) : Goodflag attend
        # Content-Disposition + Content-Type en headers.
        raw_filename = filename or 'document.pdf'
        safe_filename = raw_filename.replace('\r', '').replace('\n', '').replace('"', "'")
        upload_headers = {
            'Content-Disposition': f'attachment; filename="{safe_filename}"',
            'Content-Type': content_type,
        }

        logger.info(
            "Uploading document to workflow %s: filename=%s, size=%d",
            workflow_id, filename, len(file_content)
        )

        try:
            data = self._request('POST', f'/workflows/{workflow_id}/parts',
                                 params=params, data=file_content, headers=upload_headers)
        except GoodflagValidationError as exc:
            raise GoodflagUploadError(
                f"Document upload rejected by Goodflag: {exc}",
                status_code=getattr(exc, 'status_code', 400),
                response_data=getattr(exc, 'response_data', None),
            ) from exc

        documents = data.get('documents', [])
        doc_id = documents[0].get('id', '') if documents else ''

        logger.info(
            "Document uploaded: workflow_id=%s, document_id=%s, filename=%s",
            workflow_id, doc_id, filename
        )

        return {
            'document_id': doc_id,
            'workflow_id': workflow_id,
            'filename': filename,
            'documents': documents,
            'parts': data.get('parts', []),
            'raw': data,
        }

    def upload_documents(self, workflow_id, files_list,
                         create_documents=True,
                         ignore_attachments=False):
        """Upload plusieurs documents en une seule requête multipart."""
        params = {
            'createDocuments': str(create_documents).lower(),
            'ignoreAttachments': str(ignore_attachments).lower(),
        }

        files = []
        for i, f in enumerate(files_list):
            content = f['content']
            if isinstance(content, str):
                content = base64.b64decode(content)
            filename = f.get('filename', f'file_{i}.pdf')
            ctype = f.get('content_type', 'application/pdf')
            files.append(('document', (filename, io.BytesIO(content), ctype)))

        # Si tous les fichiers ont le même profil de signature, on le passe en global
        first_profile = files_list[0].get('signature_profile_id') if files_list else None
        if all(f.get('signature_profile_id') == first_profile for f in files_list):
            if first_profile:
                params['signatureProfileId'] = first_profile

        logger.info(
            "Uploading %d documents to workflow %s", len(files_list), workflow_id
        )

        data = self._request(
            'POST',
            f'/workflows/{workflow_id}/parts',
            params=params,
            files=files,
        )

        return {
            'workflow_id': workflow_id,
            'documents': data.get('documents', []),
            'parts': data.get('parts', []),
            'raw': data,
        }

    def start_workflow(self, workflow_id):
        """Démarre un workflow (PATCH workflowStatus -> started)."""
        logger.info("Starting Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'started'},
        )

        status = data.get('workflowStatus', 'started')
        logger.info("Goodflag workflow started: %s, status=%s", workflow_id, status)

        return {
            'workflow_id': data.get('id', workflow_id),
            'status': status,
            'raw': data,
        }

    def stop_workflow(self, workflow_id):
        """Arrête un workflow (PATCH workflowStatus -> stopped)."""
        logger.info("Stopping Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'stopped'},
        )

        return {
            'workflow_id': data.get('id', workflow_id),
            'status': data.get('workflowStatus', 'stopped'),
            'raw': data,
        }

    def archive_workflow(self, workflow_id):
        """Archive un workflow (PATCH workflowStatus -> archived)."""
        logger.info("Archiving Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'archived'},
        )

        return {
            'workflow_id': data.get('id', workflow_id),
            'status': data.get('workflowStatus', 'archived'),
            'raw': data,
        }

    def get_workflow(self, workflow_id):
        """Récupère le détail d'un workflow (GET /api/workflows/{id})."""
        data = self._request('GET', f'/workflows/{workflow_id}')

        raw_status = data.get('workflowStatus', 'draft')
        normalized_status = self.normalize_status(raw_status)

        result = {
            'workflow_id': data.get('id', workflow_id),
            'status': raw_status,
            'normalized_status': normalized_status,
            'name': data.get('name'),
            'description': data.get('description', ''),
            'progress': data.get('progress', 0),
            'steps': data.get('steps', []),
            'current_recipient_emails': data.get('currentRecipientEmails', []),
            'current_recipient_users': data.get('currentRecipientUsers', []),
            'workflow_mode': data.get('workflowMode', ''),
            'started': data.get('started'),
            'stopped': data.get('stopped'),
            'finished': data.get('finished'),
            'created': data.get('created'),
            'updated': data.get('updated'),
            'raw': data,
        }
        # Métadonnées data1-data16
        for i in range(1, MAX_METADATA_SLOTS + 1):
            val = data.get(f'data{i}')
            if val:
                result[f'data{i}'] = val

        return result

    def create_invite(self, workflow_id, recipient_email, recipient_phone=None):
        """Crée une invitation (POST /api/workflows/{id}/invite)."""
        logger.info(
            "Creating invite for workflow %s, recipient=%s",
            workflow_id, recipient_email
        )

        payload = {'recipientEmail': recipient_email}
        if recipient_phone:
            payload['recipientPhone'] = recipient_phone

        data = self._request(
            'POST',
            f'/workflows/{workflow_id}/invite',
            json_data=payload,
        )

        return {
            'invite_url': data.get('inviteUrl', ''),
            'workflow_id': workflow_id,
            'recipient_email': recipient_email,
        }

    def send_invite(self, workflow_id, recipient_email):
        """Envoie une invitation par email (POST /api/workflows/{id}/sendInvite)."""
        logger.info(
            "Sending invite for workflow %s, recipient=%s",
            workflow_id, recipient_email
        )

        data = self._request(
            'POST',
            f'/workflows/{workflow_id}/sendInvite',
            json_data={'recipientEmail': recipient_email},
        )

        return {
            'invite_url': data.get('inviteUrl', ''),
            'workflow_id': workflow_id,
            'recipient_email': recipient_email,
        }

    def download_documents(self, workflow_id, streaming=False):
        """
        Télécharge les documents signés (GET /api/workflows/{id}/downloadDocuments).

        Retourne un PDF ou un ZIP si plusieurs documents.
        """
        logger.info("Downloading signed documents for workflow %s", workflow_id)

        url = self._url(f'/workflows/{workflow_id}/downloadDocuments')
        try:
            response = self.session.get(url, timeout=self.timeout, stream=streaming)
        except requests.exceptions.Timeout:
            raise GoodflagTimeoutError(
                f"Timeout after {self.timeout}s downloading documents for {workflow_id}"
            )
        except requests.exceptions.RequestException as exc:
            raise GoodflagError(f"Error downloading documents: {exc}")

        if response.status_code >= 400:
            self._raise_for_status(response)

        content_type = response.headers.get('Content-Type', 'application/octet-stream')
        filename = _parse_content_disposition_filename(
            response.headers.get('Content-Disposition', ''), 'signed_documents'
        )

        if streaming:
            return {
                'response': response,
                'content_type': content_type,
                'filename': filename,
            }

        return {
            'content': response.content,
            'content_type': content_type,
            'filename': filename,
            'size': len(response.content),
        }

    def get_document_viewer_url(self, document_id, redirect_url=None, expired=None):
        """Génère une URL de viewer pour un document."""
        payload = {}
        if redirect_url:
            payload['redirectUrl'] = redirect_url
        if expired:
            payload['expired'] = expired

        data = self._request(
            'POST',
            f'/documents/{document_id}/viewer',
            json_data=payload,
        )

        return {
            'viewer_url': data.get('viewerUrl', ''),
            'expired': data.get('expired'),
            'raw': data,
        }

    def download_evidence_certificate(self, workflow_id, streaming=False):
        """Télécharge le certificat de preuve d'un workflow."""
        logger.info("Downloading evidence certificate for workflow %s", workflow_id)

        url = self._url(f'/workflows/{workflow_id}/downloadEvidenceCertificate')
        try:
            response = self.session.get(url, timeout=self.timeout, stream=streaming)
        except requests.exceptions.Timeout:
            raise GoodflagTimeoutError(
                f"Timeout after {self.timeout}s downloading evidence for {workflow_id}"
            )
        except requests.exceptions.RequestException as exc:
            raise GoodflagError(f"Error downloading evidence certificate: {exc}")

        if response.status_code >= 400:
            self._raise_for_status(response)

        content_type = response.headers.get('Content-Type', 'application/octet-stream')
        filename = _parse_content_disposition_filename(
            response.headers.get('Content-Disposition', ''), 'evidence_certificate'
        )

        if streaming:
            return {
                'response': response,
                'content_type': content_type,
                'filename': filename,
            }

        return {
            'content': response.content,
            'content_type': content_type,
            'filename': filename,
            'size': len(response.content),
        }

    def get_webhook_event(self, webhook_event_id):
        """Récupère un événement webhook pour re-validation (pas de HMAC côté Goodflag)."""
        return self._request('GET', f'/webhookEvents/{webhook_event_id}')

    def search_workflows(self, text=None, items_per_page=50, page_index=0,
                         sort_by='items.created', sort_order='desc',
                         filters=None):
        """Recherche dans les workflows (GET /api/workflows)."""
        params = {
            'itemsPerPage': items_per_page,
            'pageIndex': page_index,
            'sortBy': sort_by,
            'sortOrder': sort_order,
        }
        if text:
            params['text'] = text
        if filters and isinstance(filters, dict):
            params.update(filters)

        return self._request('GET', '/workflows', params=params)

    def normalize_status(self, raw_status):
        """Normalise un statut Goodflag vers Publik (draft/started/finished/refused/error)."""
        return STATUS_MAP.get(raw_status, 'error')
