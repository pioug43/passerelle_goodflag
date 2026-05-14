import base64
import logging
import re
from urllib.parse import unquote

from passerelle.utils.jsonresponse import APIError

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
    'archived': 'finished',
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


def _sanitize_filename(name):
    return (name or 'document.pdf').replace('\r', '').replace('\n', '').replace('"', "'")


class GoodflagClient:
    """Thin wrapper around Passerelle's managed requests session for the Goodflag API."""

    def __init__(self, session, base_url, user_id, timeout=30):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.user_id = user_id
        self.timeout = timeout

    def _url(self, path):
        return f'{self.base_url}/{path.lstrip("/")}'

    def _request(self, method, path, json_data=None, params=None, data=None,
                 headers=None, stream=False, cache_duration=None):
        url = self._url(path)
        kwargs = dict(
            json=json_data, params=params, data=data,
            headers=headers, timeout=self.timeout, stream=stream,
        )
        if cache_duration and method.upper() == 'GET':
            kwargs['cache_duration'] = cache_duration
        response = self.session.request(method=method, url=url, **kwargs)

        if response.status_code >= 400:
            self._raise_for_status(response)
        if stream:
            return response
        if response.status_code == 204:
            return {}
        ct = response.headers.get('Content-Type') or ''
        if 'application/json' not in ct:
            return {'raw_text': response.text}
        try:
            data = response.json()
        except ValueError:
            raise APIError(f"Invalid JSON in response (HTTP {response.status_code})",
                           http_status=502)
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
        status = response.status_code
        if status in (401, 403):
            raise APIError(f"Authentication failed: {error_msg}", http_status=status)
        if status in (400, 422):
            raise APIError(f"Validation error: {error_msg}", http_status=status, data=error_data)
        if status == 404:
            raise APIError(f"Not found: {error_msg}", http_status=404)
        raise APIError(f"Goodflag API error (HTTP {status}): {error_msg}", http_status=502)

    def test_connection(self):
        data = self._request('GET', '/version')
        return {'status': 'ok', 'version': data.get('version', str(data))}

    def create_workflow(self, name, steps, layout_id=None, metadata=None,
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
                raise APIError(
                    f"Invalid metadata keys: {', '.join(sorted(invalid))}. "
                    f"Only data1 to data{MAX_METADATA_SLOTS} are allowed.",
                    http_status=400,
                )
            for key, value in metadata.items():
                payload[key] = str(value)
        data = self._request('POST', f'/users/{self.user_id}/workflows', json_data=payload)
        return {
            'workflow_id': data.get('id', ''),
            'status': data.get('workflowStatus', 'draft'),
        }

    def upload_document(self, workflow_id, file_content, filename,
                        content_type='application/pdf', signature_profile_id=None):
        if content_type not in ALLOWED_CONTENT_TYPES:
            raise APIError(
                f"Content type '{content_type}' not allowed. "
                f"Allowed: {', '.join(ALLOWED_CONTENT_TYPES)}",
                http_status=400,
            )
        if isinstance(file_content, (str, memoryview)):
            file_content = base64.b64decode(file_content) if isinstance(file_content, str) else bytes(file_content)
        if len(file_content) > MAX_UPLOAD_SIZE:
            raise APIError(f"File too large ({len(file_content)} bytes). Max: {MAX_UPLOAD_SIZE}", http_status=400)

        params = {'createDocuments': 'true'}
        if signature_profile_id:
            params['signatureProfileId'] = signature_profile_id
        if content_type != 'application/pdf':
            params['convertToPdf'] = 'true'

        safe_filename = _sanitize_filename(filename)
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
        }

    def patch_workflow_status(self, workflow_id, status):
        data = self._request('PATCH', f'/workflows/{workflow_id}',
                             json_data={'workflowStatus': status})
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': data.get('workflowStatus', status),
        }

    def get_workflow(self, workflow_id, cache_duration=None):
        data = self._request('GET', f'/workflows/{workflow_id}', cache_duration=cache_duration)
        raw_status = data.get('workflowStatus', 'draft')
        return {
            'workflow_id': data.get('id', workflow_id),
            'status': raw_status,
            'normalized_status': STATUS_MAP.get(raw_status, 'error'),
            'name': data.get('name'),
            'progress': data.get('progress', 0),
            'steps': data.get('steps', []),
        }

    def send_invite(self, workflow_id, recipient_email):
        data = self._request('POST', f'/workflows/{workflow_id}/sendInvite',
                             json_data={'recipientEmail': recipient_email})
        return {
            'invite_url': data.get('inviteUrl', ''),
            'workflow_id': workflow_id,
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
            'document_id': document_id,
        }

    def download_signed_documents(self, workflow_id):
        response = self._request('GET', f'/workflows/{workflow_id}/downloadDocuments', stream=True)
        return {
            'response': response,
            'content_type': response.headers.get('Content-Type', 'application/octet-stream'),
            'filename': _sanitize_filename(_parse_content_disposition_filename(
                response.headers.get('Content-Disposition', ''), 'signed_documents',
            )),
        }

    def search_workflows(self, text=None, items_per_page=50, page_index=0, cache_duration=None):
        params = {
            'itemsPerPage': items_per_page,
            'pageIndex': page_index,
            'sortBy': 'items.created',
            'sortOrder': 'desc',
        }
        if text:
            params['text'] = text
        return self._request('GET', '/workflows', params=params, cache_duration=cache_duration)
