import base64
import json

import pytest
import responses

from passerelle_goodflag.client import GoodflagClient, _sanitize_for_log
from passerelle_goodflag.exceptions import (
    GoodflagAuthError,
    GoodflagError,
    GoodflagNotFoundError,
    GoodflagRateLimitError,
    GoodflagTimeoutError,
    GoodflagValidationError,
)

BASE_URL = 'https://api.goodflag.test/api'
TOKEN = 'act_test.secret_token_value'
USER_ID = 'usr_TestUser123'


@pytest.fixture
def client():
    return GoodflagClient(base_url=BASE_URL, access_token=TOKEN, timeout=5)


class TestSanitizeForLog:
    def test_masks_token(self):
        data = {'access_token': 'secret123', 'name': 'test'}
        result = _sanitize_for_log(data)
        assert result['access_token'] == '***MASKED***'
        assert result['name'] == 'test'

    def test_masks_nested(self):
        data = {'auth': {'token': 'secret'}, 'name': 'ok'}
        result = _sanitize_for_log(data)
        assert result['auth']['token'] == '***MASKED***'

    def test_non_dict(self):
        assert _sanitize_for_log("hello") == "hello"
        assert _sanitize_for_log(None) is None


class TestClientInit:
    def test_requires_base_url(self):
        with pytest.raises(GoodflagValidationError):
            GoodflagClient(base_url='', access_token='token')

    def test_requires_token(self):
        with pytest.raises(GoodflagValidationError):
            GoodflagClient(base_url='https://example.com', access_token='')

    def test_strips_trailing_slash(self):
        c = GoodflagClient(base_url='https://example.com/', access_token='t')
        assert c.base_url == 'https://example.com'


class TestTestConnection:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            json='sgs-wm-webapp:1.19.4-RC1',
            status=200,
        )
        result = client.test_connection()
        assert result['status'] == 'ok'
        assert 'successful' in result['message'].lower()
        assert '1.19.4' in result['version']

    @responses.activate
    def test_auth_failure(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            json={'status': 403, 'error': 'Forbidden', 'message': 'Missing bearer token', 'code': 'MissingBearerToken'},
            status=403,
        )
        result = client.test_connection()
        assert result['status'] == 'error'
        assert 'authentication' in result['message'].lower()

    @responses.activate
    def test_server_error(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            json={'error': 'Internal server error'},
            status=500,
        )
        result = client.test_connection()
        assert result['status'] == 'error'


class TestCreateWorkflow:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json={
                'id': 'wfl_001',
                'workflowStatus': 'draft',
                'name': 'Test WF',
                'workflowMode': 'FULL',
                'progress': 0,
                'steps': [],
                'created': 1700000000000,
                'updated': 1700000000000,
            },
            status=200,
        )
        result = client.create_workflow(
            user_id=USER_ID,
            name='Test WF',
            steps=[{
                'stepType': 'signature',
                'recipients': [{
                    'consentPageId': 'cop_Test',
                    'email': 'signer@example.com',
                    'firstName': 'Jean',
                    'lastName': 'Dupont',
                }],
                'maxInvites': 5,
            }],
            description='Test description',
            workflow_mode='FULL',
            metadata={'data1': 'DEM-001', 'data2': 'RH'},
            external_ref='DEM-001',
        )
        assert result['workflow_id'] == 'wfl_001'
        assert result['status'] == 'draft'

        sent = responses.calls[0].request
        body = json.loads(sent.body)
        assert body['name'] == 'Test WF'
        assert body['workflowMode'] == 'FULL'
        assert body['steps'][0]['recipients'][0]['email'] == 'signer@example.com'
        assert body['data1'] == 'DEM-001'
        assert body['data2'] == 'RH'

    @responses.activate
    def test_validation_error(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json={
                'status': 400,
                'error': 'Bad Request',
                'message': 'A request field has an incorrect value.',
                'code': 'InvalidRequestField',
            },
            status=400,
        )
        with pytest.raises(GoodflagValidationError):
            client.create_workflow(
                user_id=USER_ID,
                name='',
                steps=[],
            )

    @responses.activate
    def test_auth_error(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json={
                'status': 401,
                'error': 'Unauthorized',
                'message': 'Missing bearer token.',
                'code': 'MissingBearerToken',
            },
            status=401,
        )
        with pytest.raises(GoodflagAuthError):
            client.create_workflow(
                user_id=USER_ID,
                name='Test',
                steps=[{'stepType': 'signature', 'recipients': []}],
            )


class TestUploadDocument:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_001/parts',
            json={
                'documents': [{
                    'id': 'doc_001',
                    'workflowId': 'wfl_001',
                    'parts': [{'filename': 'test.pdf', 'contentType': 'application/pdf', 'size': 100}],
                }],
                'parts': [{'filename': 'test.pdf', 'contentType': 'application/pdf', 'size': 100}],
                'ignoredAttachments': 0,
            },
            status=200,
        )
        result = client.upload_document(
            workflow_id='wfl_001',
            file_content=b'%PDF-1.4 fake content',
            filename='test.pdf',
            signature_profile_id='sip_Profile',
        )
        assert result['document_id'] == 'doc_001'
        assert result['workflow_id'] == 'wfl_001'

        sent = responses.calls[0].request
        assert 'createDocuments=true' in sent.url
        assert 'signatureProfileId=sip_Profile' in sent.url

        assert sent.headers.get('Content-Type') == 'application/pdf'
        assert 'filename="test.pdf"' in sent.headers.get('Content-Disposition', '')
        assert b'%PDF-1.4' in sent.body

    @responses.activate
    def test_base64_content(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_001/parts',
            json={
                'documents': [{'id': 'doc_002'}],
                'parts': [],
                'ignoredAttachments': 0,
            },
            status=200,
        )
        b64_content = base64.b64encode(b'%PDF-1.4 content').decode()
        result = client.upload_document(
            workflow_id='wfl_001',
            file_content=b64_content,
            filename='b64.pdf',
        )
        assert result['document_id'] == 'doc_002'

    def test_invalid_content_type(self, client):
        with pytest.raises(GoodflagValidationError, match='not allowed'):
            client.upload_document(
                workflow_id='wfl_001',
                file_content=b'<html>',
                filename='test.html',
                content_type='text/html',
            )

    def test_file_too_large(self, client):
        large_content = b'x' * (50 * 1024 * 1024 + 1)
        with pytest.raises(GoodflagValidationError, match='too large'):
            client.upload_document(
                workflow_id='wfl_001',
                file_content=large_content,
                filename='huge.pdf',
            )


class TestStartWorkflow:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_001',
            json={
                'id': 'wfl_001',
                'workflowStatus': 'started',
                'started': 1700000100000,
            },
            status=200,
        )
        result = client.start_workflow('wfl_001')
        assert result['status'] == 'started'

        sent = responses.calls[0].request
        body = json.loads(sent.body)
        assert body['workflowStatus'] == 'started'

    @responses.activate
    def test_not_found(self, client):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_bad',
            json={
                'status': 404,
                'error': 'Not Found',
                'message': 'The specified workflow can not be found.',
                'code': 'WorkflowNotFound',
            },
            status=404,
        )
        with pytest.raises(GoodflagNotFoundError):
            client.start_workflow('wfl_bad')


class TestGetWorkflow:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_001',
            json={
                'id': 'wfl_001',
                'workflowStatus': 'finished',
                'name': 'WF Test',
                'workflowMode': 'FULL',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
                'data1': 'DEM-001',
            },
            status=200,
        )
        result = client.get_workflow('wfl_001')
        assert result['workflow_id'] == 'wfl_001'
        assert result['status'] == 'finished'
        assert result['normalized_status'] == 'finished'
        assert result['progress'] == 100
        assert result['data1'] == 'DEM-001'


class TestCreateInvite:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_001/invite',
            json={
                'inviteUrl': 'https://goodflag.test/invite?token=eyJtest',
            },
            status=200,
        )
        result = client.create_invite('wfl_001', 'signer@example.com')
        assert result['invite_url'].startswith('https://')
        assert result['recipient_email'] == 'signer@example.com'

        sent = responses.calls[0].request
        body = json.loads(sent.body)
        assert body['recipientEmail'] == 'signer@example.com'


class TestDownloadDocuments:
    @responses.activate
    def test_success(self, client):
        pdf_bytes = b'%PDF-1.4 signed content'
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_001/downloadDocuments',
            body=pdf_bytes,
            content_type='application/pdf',
            headers={
                'Content-Disposition': 'attachment; filename="signed.pdf"',
            },
            status=200,
        )
        result = client.download_documents('wfl_001')
        assert result['content'] == pdf_bytes
        assert result['content_type'] == 'application/pdf'
        assert result['filename'] == 'signed.pdf'
        assert result['size'] == len(pdf_bytes)

    @responses.activate
    def test_not_found(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_bad/downloadDocuments',
            json={
                'status': 404,
                'error': 'Not Found',
                'message': 'The specified workflow can not be found.',
                'code': 'WorkflowNotFound',
            },
            status=404,
        )
        with pytest.raises(GoodflagNotFoundError):
            client.download_documents('wfl_bad')


class TestGetWebhookEvent:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/webhookEvents/wbe_Event001',
            json={
                'id': 'wbe_Event001',
                'eventType': 'workflowFinished',
                'workflowId': 'wfl_001',
                'webhookId': 'wbh_Webhook001',
                'created': 1700000500000,
                'updated': 1700000500000,
            },
            status=200,
        )
        result = client.get_webhook_event('wbe_Event001')
        assert result['id'] == 'wbe_Event001'
        assert result['eventType'] == 'workflowFinished'
        assert result['workflowId'] == 'wfl_001'


class TestNormalizeStatus:
    def test_known_statuses(self, client):
        assert client.normalize_status('draft') == 'draft'
        assert client.normalize_status('started') == 'started'
        assert client.normalize_status('finished') == 'finished'
        assert client.normalize_status('stopped') == 'refused'

    def test_unknown_status(self, client):
        assert client.normalize_status('something_new') == 'error'


class TestTimeout:
    @responses.activate
    def test_timeout_raises(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            body=responses.ConnectionError("timeout"),
        )
        result = client.test_connection()
        assert result['status'] == 'error'


class TestStopWorkflowClient:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={'id': 'wfl_Test001', 'workflowStatus': 'stopped'},
            status=200,
        )
        result = client.stop_workflow('wfl_Test001')
        assert result['status'] == 'stopped'
        assert result['workflow_id'] == 'wfl_Test001'


class TestArchiveWorkflowClient:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={'id': 'wfl_Test001', 'workflowStatus': 'archived'},
            status=200,
        )
        result = client.archive_workflow('wfl_Test001')
        assert result['status'] == 'archived'


class TestSendInviteClient:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/sendInvite',
            json={'inviteUrl': 'https://sign.example.com/invite/xyz'},
            status=200,
        )
        result = client.send_invite('wfl_Test001', 'signer@example.com')
        assert result['invite_url'] == 'https://sign.example.com/invite/xyz'
        assert result['workflow_id'] == 'wfl_Test001'
        assert result['recipient_email'] == 'signer@example.com'
        assert 'raw' not in result


class TestUploadDocumentsClient:
    @responses.activate
    def test_multi_file(self, client):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json={'id': 'doc_Doc001', 'filename': 'test.pdf'},
            status=200,
        )
        files = [
            ('test.pdf', b'%PDF-1.4 content', 'application/pdf'),
        ]
        result = client.upload_documents('wfl_Test001', files)
        assert 'workflow_id' in result


class TestSearchWorkflowsClient:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows',
            json={
                'items': [],
                'totalItems': 0,
                'itemsPerPage': 50,
                'pageIndex': 0,
            },
            status=200,
        )
        result = client.search_workflows()
        assert 'items' in result or result.get('totalItems') == 0

    @responses.activate
    def test_with_text_filter(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows',
            json={
                'items': [],
                'totalItems': 0,
                'itemsPerPage': 50,
                'pageIndex': 0,
            },
            status=200,
        )
        client.search_workflows(text='convention')
        sent = responses.calls[0].request
        assert 'text=convention' in sent.url


class TestRateLimitClient:
    @responses.activate
    def test_429_raises_rate_limit_error(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={'message': 'Too Many Requests'},
            headers={'Retry-After': '30'},
            status=429,
        )
        with pytest.raises(GoodflagRateLimitError) as exc_info:
            client.get_workflow('wfl_Test001')
        assert exc_info.value.retry_after == 30


class TestDownloadEvidenceCertificateClient:
    @responses.activate
    def test_success(self, client):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001/downloadEvidenceCertificate',
            body=b'%PDF-1.4 evidence',
            headers={
                'Content-Type': 'application/pdf',
                'Content-Disposition': 'attachment; filename="evidence.pdf"',
            },
            status=200,
        )
        result = client.download_evidence_certificate('wfl_Test001')
        assert result['content'] == b'%PDF-1.4 evidence'
        assert result['filename'] == 'evidence.pdf'
        assert result['content_type'] == 'application/pdf'
