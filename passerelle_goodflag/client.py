import base64
import logging
import re
from urllib.parse import unquote

import requests

from .exceptions import GoodflagAuthError, GoodflagError, GoodflagValidationError

logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024
MAX_METADATA_SLOTS = 16

ALLOWED_CONTENT_TYPES = (
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/jpeg',
    'image/png',
    'image/webp',
)

STATUS_MAP = {
    'draft': 'draft',
    'started': 'started',
    'stopped': 'refused',
    'finished': 'finished',
    'archived': 'archived',
}


def _parse_content_disposition_filename(header, default):
    if not header:
        return default
    m = re.search(r"filename\*\s*=\s*[^']*''([^\s;]+)", header, re.IGNORECASE)
    if m:
        return unquote(m.group(1)) or default
    m = re.search(r'filename\s*=\s*"([^"]*)"', header, re.IGNORECASE)
    if m:
        return m.group(1) or default
    m = re.search(r'filename\s*=\s*([^\s;]+)', header, re.IGNORECASE)
    if m:
        return m.group(1).strip("'") or default
    return default


class GoodflagClient:
    def __init__(self, base_url, access_token, timeout=30, verify_ssl=True):
        if not base_url:
            raise GoodflagValidationError("base_url is required")
        if not access_token:
            raise GoodflagValidationError("access_token is required")
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        })
        self.session.verify = verify_ssl

    def _url(self, path):
        return f'{self.base_url}/{path.lstrip("/")}'

    def _request(self, method, path, json_data=None, params=None, data=None,
                 headers=None, stream=False):
        url = self._url(path)
        try:
            response = self.session.request(
                method=method, url=url, json=json_data, params=params,
                data=data, headers=headers, timeout=self.timeout, stream=stream,
            )
        except requests.exceptions.RequestException as exc:
            raise GoodflagError(f"HTTP error calling {method} {url}: {exc}")

        if response.status_code >= 400:
            self._raise_for_status(response)

        if stream:
            return response
        if response.status_code == 204:
            return {}
        if 'application/json' not in response.headers.get('Content-Type', ''):
            return {'raw_text': response.text}
        try:
            data = response.json()
        except ValueError:
            raise GoodflagError(f"Invalid JSON in response (HTTP {response.status_code})",
                                status_code=response.status_code)
        if isinstance(data, str):
            return {'version': data}
        return data

    def _raise_for_status(self, response):
        try:
            error_data = response.json()
            if not isinstance(error_data, dict):
                error_data = {'raw': str(error_data)[:500]}
        except ValueError:
            error_data = {'raw': response.text[:500]}
        error_msg = error_data.get('message') or error_data.get('error') or str(error_data)
        logger.warning("Goodflag API error: HTTP %s - %s", response.status_code, error_msg)
        if response.status_code in (401, 403):
            raise GoodflagAuthError(f"Authentication failed: {error_msg}",
                                    status_code=response.status_code, response_data=error_data)
        if response.status_code in (400, 404, 422):
            raise GoodflagValidationError(f"API error: {error_msg}",
                                          status_code=response.status_code, response_data=error_data)
        raise GoodflagError(f"API error (HTTP {response.status_code}): {error_msg}",
                            status_code=response.status_code, response_data=error_data)

    def test_connection(self):
        try:
            data = self._request('GET', '/version')
            return {'status': 'ok', 'version': data.get('version', str(data))}
        except GoodflagError as exc:
            return {'status': 'error', 'message': str(exc)}

    def create_workflow(self, user_id, name, steps, layout_id=None, metadata=None,
                        workflow_mode='FULL', description=None):
        payload = {'name': name, 'steps': steps, 'workflowMode': workflow_mode}
        if description:
            payload['description'] = description
        if layout_id:
            payload['layoutId'] = layout_id
        if metadata:
            valid_keys = {f'data{i}' for i in range(1, MAX_METADATA_SLOTS + 1)}
            invalid = set(metadata) - valid_keys
            if invalid:
                raise GoodflagValidationError(
                    f"Invalid metadata keys: {', '.join(sorted(invalid))}. "
                    f"Only data1 to data{MAX_METADATA_SLOTS} are allowed."
                )
            for key, value in metadata.items():
                payload[key] = str(value)
        data = self._request('POST', f'/users/{user_id}/workflows', json_data=payload)
        return {
            'workflow_id': data.get('id', ''),
            'status': data.get('workflowStatus', 'draft'),
            'raw': data,
        }

    def upload_document(self, workflow_id, file_content, filename,
                        content_type='application/pdf', signature_profile_id=None):
        if content_type not in ALLOWED_CONTENT_TYPES:
            raise GoodflagValidationError(
                f"Content type '{content_type}' not allowed. "
                f"Allowed: {', '.join(ALLOWED_CONTENT_TYPES)}"
            )
        if isinstance(file_content, str):
            file_content = base64.b64decode(file_content)
        if len(file_content) > MAX_UPLOAD_SIZE:
            raise GoodflagValidationError(
                f"File too large ({len(file_content)} bytes). Max: {MAX_UPLOAD_SIZE} bytes"
            )

        params = {'createDocuments': 'true'}
        if signature_profile_id:
            params['signatureProfileId'] = signature_profile_id
        if content_type != 'application/pdf':
            params['convertToPdf'] = 'true'

        # CRLF protection on filename — would otherwise allow header injection
        # via Content-Disposition through the Goodflag Apache proxy.
        safe_filename = (filename or 'document.pdf').replace('\r', '').replace('\n', '').replace('"', "'")
        headers = {
            'Content-Disposition': f'attachment; filename="{safe_filename}"',
            'Content-Type': content_type,
        }
        data = self._request('POST', f'/workflows/{workflow_id}/parts',
                             params=params, data=file_content, headers=headers)
        documents = data.get('documents', [])
        return {
            'document_id': documents[0].get('id', '') if documents else '',
            'workflow_id': workflow_id,
            'filename': filename,
            'documents': documents,
            'parts': data.get('parts', []),
        }

    def patch_workflow_status(self, workflow_id, status):
        data = self._request('PATCH', f'/workflows/{workflow_id}',
                             json_data={'workflowStatus': status})
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': data.get('workflowStatus', status),
        }

    def get_workflow(self, workflow_id):
        data = self._request('GET', f'/workflows/{workflow_id}')
        raw_status = data.get('workflowStatus', 'draft')
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': raw_status,
            'normalized_status': STATUS_MAP.get(raw_status, 'error'),
            'name': data.get('name'),
            'progress': data.get('progress', 0),
            'steps': data.get('steps', []),
            'raw': data,
        }

    def send_invite(self, workflow_id, recipient_email):
        data = self._request(
            'POST', f'/workflows/{workflow_id}/sendInvite',
            json_data={'recipientEmail': recipient_email},
        )
        return {
            'invite_url': data.get('inviteUrl', ''),
            'workflow_id': workflow_id,
            'recipient_email': recipient_email,
        }

    def get_document_viewer_url(self, document_id, redirect_url=None, expired=None):
        payload = {}
        if redirect_url:
            payload['redirectUrl'] = redirect_url
        if expired:
            payload['expired'] = expired
        data = self._request('POST', f'/documents/{document_id}/viewer', json_data=payload)
        return {
            'viewer_url': data.get('viewerUrl', ''),
            'expired': data.get('expired'),
            'document_id': document_id,
        }

    def download_signed_documents(self, workflow_id):
        response = self._request('GET', f'/workflows/{workflow_id}/downloadDocuments', stream=True)
        return {
            'response': response,
            'content_type': response.headers.get('Content-Type', 'application/octet-stream'),
            'filename': _parse_content_disposition_filename(
                response.headers.get('Content-Disposition', ''), 'signed_documents',
            ),
        }

    def search_workflows(self, text=None, items_per_page=50, page_index=0):
        params = {
            'itemsPerPage': items_per_page,
            'pageIndex': page_index,
            'sortBy': 'items.created',
            'sortOrder': 'desc',
        }
        if text:
            params['text'] = text
        return self._request('GET', '/workflows', params=params)
