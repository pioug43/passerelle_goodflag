"""
Client HTTP dédié pour l'API Goodflag Workflow Manager.

Centralise tous les appels HTTP vers l'API Goodflag, gère l'authentification
Bearer, les erreurs, les timeouts, et expose des méthodes métier claires.

Points d'intégration API Goodflag (v1.19.4) :
- Authentification par header Authorization: Bearer <token>
- API REST JSON, base URL de type https://<host>/api
- Endpoints principaux :
    GET    /api/version                           -> test de connectivité
    POST   /api/users/{userId}/workflows          -> créer un workflow
    GET    /api/workflows/{id}                    -> détail d'un workflow
    PATCH  /api/workflows/{id}                    -> mettre à jour / démarrer
    POST   /api/workflows/{id}/parts              -> upload document (multipart)
    GET    /api/workflows/{id}/downloadDocuments   -> télécharger docs signés
    GET    /api/workflows/{id}/downloadEvidences   -> télécharger preuves
    GET    /api/webhookEvents/{id}                 -> vérifier un événement webhook
    POST   /api/workflows/{id}/invite              -> créer une invitation
    POST   /api/workflows/{id}/sendInvite          -> envoyer une invitation
"""

import base64
import io
import logging

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

# Taille max d'upload : 50 Mo
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

ALLOWED_CONTENT_TYPES = (
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # DOCX
    'image/jpeg',
    'image/png',
    'image/webp',
)

# Mapping des statuts Goodflag (champ workflowStatus) vers des statuts
# normalisés Publik. Les valeurs réelles de l'API sont :
# draft, started, stopped, finished
STATUS_MAP = {
    'draft': 'draft',
    'started': 'started',
    'stopped': 'refused',
    'finished': 'finished',
    'archived': 'archived',
}

# Nombre maximum de champs de métadonnées Goodflag
MAX_METADATA_SLOTS = 16


def _parse_content_disposition_filename(header, default):
    """
    Extrait le nom de fichier depuis un header Content-Disposition (RFC 6266).

    Gère :
    - filename="foo.pdf"          (RFC 2183 basique)
    - filename*=UTF-8''foo%20bar  (RFC 5987 — priorité si présent)
    """
    import re
    from urllib.parse import unquote
    if not header:
        return default
    # RFC 5987 : filename*=charset''encoded_value
    m = re.search(r"filename\*\s*=\s*[^']*''([^\s;]+)", header, re.IGNORECASE)
    if m:
        return unquote(m.group(1)) or default
    # RFC 2183 : filename="value" ou filename=value
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
    """Client HTTP pour l'API Goodflag Workflow Manager."""

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

        # Stratégie de retry automatique
        # Retry uniquement sur les méthodes idempotentes (GET, HEAD, OPTIONS).
        # POST/PATCH sont exclus : un retry automatique pourrait créer des doublons
        # (ex: plusieurs workflows identiques ou plusieurs démarrages).
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
        """Construit l'URL complète à partir d'un chemin relatif."""
        return f'{self.base_url}/{path.lstrip("/")}'

    def _request(self, method, path, json_data=None, params=None, files=None,
                 data=None, headers=None, raw_response=False):
        """
        Effectue une requête HTTP et gère les erreurs de manière centralisée.

        Args:
            method: GET, POST, PUT, DELETE, PATCH
            path: chemin relatif (ex: /workflows)
            json_data: corps JSON
            params: query params
            files: fichiers pour upload multipart
            data: corps binaire brut
            headers: headers additionnels
            raw_response: si True, retourne l'objet Response brut

        Returns:
            dict ou Response selon raw_response
        """
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

        # L'endpoint /api/version retourne une chaîne JSON simple
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

        # La réponse peut être une string (ex: version)
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

        if response.status_code == 401:
            raise GoodflagAuthError(
                f"Authentication failed: {error_msg} (URL: {response.url})",
                status_code=401,
                response_data=error_data,
            )
        elif response.status_code == 403:
            raise GoodflagAuthError(
                f"Forbidden: {error_msg} (URL: {response.url})",
                status_code=403,
                response_data=error_data,
            )
        elif response.status_code == 404:
            raise GoodflagNotFoundError(
                f"Not found: {error_msg} (URL: {response.url})",
                status_code=404,
                response_data=error_data,
            )
        elif response.status_code in (400, 422):
            raise GoodflagValidationError(
                f"Validation error: {error_msg} (URL: {response.url})",
                status_code=response.status_code,
                response_data=error_data,
            )
        elif response.status_code == 429:
            retry_after = None
            try:
                retry_after = int(response.headers.get('Retry-After', 60))
            except (TypeError, ValueError):
                retry_after = 60
            raise GoodflagRateLimitError(
                f"Rate limit exceeded, retry after {retry_after}s (URL: {response.url})",
                status_code=429,
                retry_after=retry_after,
                response_data=error_data,
            )
        else:
            raise GoodflagError(
                f"API error (HTTP {response.status_code}): {error_msg} (URL: {response.url})",
                status_code=response.status_code,
                response_data=error_data,
            )

    # ------------------------------------------------------------------ #
    # Méthodes métier
    # ------------------------------------------------------------------ #

    def test_connection(self):
        """
        Teste la connexion à l'API Goodflag via GET /api/version.

        Retourne la version de l'application si la connexion est OK.
        """
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
        Crée un workflow Goodflag.

        L'API Goodflag attend :
        POST /api/users/{userId}/workflows
        {
            "name": "...",
            "description": "...",
            "workflowMode": "FULL" | "SINGLE_SIGNER",
            "steps": [
                {
                    "stepType": "signature" | "approval",
                    "recipients": [
                        {
                            "consentPageId": "cop_...",
                            "email": "...",
                            "firstName": "...",
                            "lastName": "...",
                            ...
                        }
                    ],
                    "maxInvites": 5,
                    ...
                }
            ],
            "layoutId": "...",
            "data1": "...", "data2": "...", ...
        }

        Args:
            user_id: identifiant de l'utilisateur propriétaire du workflow
            name: nom du workflow
            steps: liste des étapes (chaque étape contient stepType et recipients)
            description: description optionnelle
            workflow_mode: FULL ou SINGLE_SIGNER (défaut: FULL)
            notified_events: types d'événements notifiés au propriétaire
            watchers: observateurs du workflow
            template_id: identifiant du template
            allow_consolidation: activer la consolidation
            layout_id: identifiant du layout (requis pour les métadonnées)
            metadata: dict avec clés data1-data16 pour les métadonnées
            external_ref: référence externe (stockée dans data1 si pas de
                         mapping explicite, et aussi en local)
        """
        payload = {
            'name': name,
            'steps': steps,
        }
        if description:
            payload['description'] = description
        if workflow_mode:
            payload['workflowMode'] = workflow_mode
        else:
            payload['workflowMode'] = 'FULL'
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

        # Métadonnées Goodflag : champs data1-data16
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
            "Goodflag workflow created: workflow_id=%s, status=%s, external_ref=%s",
            workflow_id, status, external_ref
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
        Upload un document dans un workflow Goodflag via l'endpoint parts.

        L'API Goodflag utilise :
        POST /api/workflows/{workflowId}/parts?createDocuments=true
             &signatureProfileId=...

        Le document est envoyé en multipart form-data.

        Args:
            workflow_id: identifiant du workflow
            file_content: contenu binaire du fichier (bytes)
            filename: nom du fichier
            content_type: type MIME (seul application/pdf autorisé par défaut)
            signature_profile_id: profil de signature pour ce document.
                Si vide, le document sera une pièce jointe (attachment).
            create_documents: créer automatiquement les documents (défaut: True)
            ignore_attachments: ignorer les pièces jointes (défaut: False)
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

        # Conversion automatique en PDF pour les formats non-PDF
        if content_type != 'application/pdf':
            params['convertToPdf'] = 'true'

        # L'API Goodflag attend le fichier en corps binaire brut
        # (pas multipart) avec Content-Disposition et Content-Type en headers.
        # Un filename vide dans Content-Disposition provoque un rejet HTTP 400
        # par le proxy Apache devant l'application Goodflag.
        # Sanitisation du nom de fichier : supprimer les caractères de contrôle
        # qui permettraient une injection de header HTTP (CRLF injection).
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

        # La réponse contient documents[] avec les documents créés
        documents = data.get('documents', [])
        doc_id = ''
        if documents:
            doc_id = documents[0].get('id', '')

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
        """
        Upload plusieurs documents d'un coup dans un workflow Goodflag.

        files_list doit être une liste de dict :
        [{'content': b'...', 'filename': 'a.pdf', 'content_type': '...',
          'signature_profile_id': 'sip_...'}, ...]
        """
        params = {
            'createDocuments': str(create_documents).lower(),
            'ignoreAttachments': str(ignore_attachments).lower(),
        }

        # Construction du multipart avec plusieurs fichiers
        files = []
        for i, f in enumerate(files_list):
            content = f['content']
            if isinstance(content, str):
                content = base64.b64decode(content)

            filename = f.get('filename', f'file_{i}.pdf')
            ctype = f.get('content_type', 'application/pdf')
            # Note: signatureProfileId is global for the whole request in /parts
            files.append(('document', (filename, io.BytesIO(content), ctype)))

        # Si un seul profil pour tous :
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
        """
        Démarre un workflow Goodflag en passant son statut à 'started'.

        L'API Goodflag utilise :
        PATCH /api/workflows/{workflowId}
        {"workflowStatus": "started"}
        """
        logger.info("Starting Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'started'},
        )

        status = data.get('workflowStatus', 'started')
        logger.info(
            "Goodflag workflow started: workflow_id=%s, status=%s",
            workflow_id, status
        )

        return {
            'workflow_id': data.get('id', workflow_id),
            'status': status,
            'raw': data,
        }

    def stop_workflow(self, workflow_id):
        """
        Arrête un workflow Goodflag (statut 'stopped').

        PATCH /api/workflows/{workflowId}
        {"workflowStatus": "stopped"}
        """
        logger.info("Stopping Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'stopped'},
        )

        status = data.get('workflowStatus', 'stopped')
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': status,
            'raw': data,
        }

    def archive_workflow(self, workflow_id):
        """
        Archive un workflow Goodflag (statut 'archived').

        PATCH /api/workflows/{workflowId}
        {"workflowStatus": "archived"}
        """
        logger.info("Archiving Goodflag workflow: %s", workflow_id)

        data = self._request(
            'PATCH',
            f'/workflows/{workflow_id}',
            json_data={'workflowStatus': 'archived'},
        )

        status = data.get('workflowStatus', 'archived')
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': status,
            'raw': data,
        }

    def get_workflow(self, workflow_id):
        """
        Récupère le détail d'un workflow Goodflag.

        GET /api/workflows/{workflowId}
        """
        data = self._request('GET', f'/workflows/{workflow_id}')

        raw_status = data.get('workflowStatus', 'draft')
        normalized_status = self.normalize_status(raw_status)

        return {
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
            # Métadonnées data1-data16
            **{f'data{i}': data.get(f'data{i}', '')
               for i in range(1, MAX_METADATA_SLOTS + 1)
               if data.get(f'data{i}')},
            'raw': data,
        }

    def create_invite(self, workflow_id, recipient_email, recipient_phone=None):
        """
        Crée une invitation pour un destinataire d'un workflow.

        POST /api/workflows/{workflowId}/invite
        {"recipientEmail": "...", "recipientPhone": "..."}

        Retourne l'URL d'invitation.
        """
        logger.info(
            "Creating invite for workflow %s, recipient=%s, phone=%s",
            workflow_id, recipient_email, recipient_phone
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
        """
        Envoie une invitation par email à un destinataire.

        POST /api/workflows/{workflowId}/sendInvite
        {"recipientEmail": "..."}
        """
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
        Télécharge les documents signés d'un workflow terminé.

        GET /api/workflows/{workflowId}/downloadDocuments
        Retourne un PDF ou un ZIP si plusieurs documents.
        Si streaming=True, retourne la réponse brute pour un StreamingHttpResponse.
        """
        logger.info("Downloading signed documents for workflow %s", workflow_id)

        url = self._url(f'/workflows/{workflow_id}/downloadDocuments')
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                stream=streaming,
            )
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
        """
        Génère une URL de viewer pour un document (visualisation / placement).

        POST /api/documents/{documentId}/viewer
        """
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
        """
        Télécharge le certificat de preuve d'un workflow.

        GET /api/workflows/{workflowId}/downloadEvidenceCertificate
        Si streaming=True, retourne la réponse brute pour un StreamingHttpResponse.
        """
        logger.info("Downloading evidence certificate for workflow %s", workflow_id)

        url = self._url(f'/workflows/{workflow_id}/downloadEvidenceCertificate')
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                stream=streaming,
            )
        except requests.exceptions.Timeout:
            raise GoodflagTimeoutError(
                f"Timeout after {self.timeout}s downloading evidence certificate for {workflow_id}"
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
        """
        Récupère un événement webhook pour validation.

        GET /api/webhookEvents/{webhookEventId}

        Utilisé pour re-valider les événements webhook reçus,
        car Goodflag ne signe pas ses webhooks (pas de HMAC).
        """
        data = self._request('GET', f'/webhookEvents/{webhook_event_id}')
        return data

    def search_workflows(self, text=None, items_per_page=50, page_index=0,
                         sort_by='items.created', sort_order='desc',
                         filters=None):
        """
        Recherche dans les workflows.

        GET /api/workflows?text=...&itemsPerPage=50&pageIndex=0
        """
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

        data = self._request('GET', '/workflows', params=params)
        return data

    def normalize_status(self, raw_status):
        """
        Normalise un statut Goodflag en statut simplifié Publik.

        Statuts Goodflag réels : draft, started, stopped, finished
        Statuts normalisés Publik : draft, started, pending, finished,
                                     refused, cancelled, error
        """
        return STATUS_MAP.get(raw_status, 'error')
