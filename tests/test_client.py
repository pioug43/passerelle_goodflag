"""Tests unitaires du client HTTP Goodflag."""

import base64
import json

import pytest
import responses

from passerelle_goodflag.client import GoodflagClient
from passerelle_goodflag.exceptions import GoodflagAuthError, GoodflagError, GoodflagValidationError

BASE_URL = 'https://api.goodflag.test/api'
TOKEN = 'act_test.secret_token_value'
USER_ID = 'usr_TestUser123'


@pytest.fixture
def client():
    return GoodflagClient(base_url=BASE_URL, access_token=TOKEN, timeout=5)


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
        responses.add(responses.GET, f'{BASE_URL}/version',
                      json='sgs-wm-webapp:1.19.4-RC1', status=200)
        result = client.test_connection()
        assert result['status'] == 'ok'
        assert '1.19.4' in result['version']

    @responses.activate
    def test_auth_failure(self, client):
        responses.add(responses.GET, f'{BASE_URL}/version',
                      json={'message': 'Missing bearer token'}, status=403)
        result = client.test_connection()
        assert result['status'] == 'error'

    @responses.activate
    def test_server_error(self, client):
        responses.add(responses.GET, f'{BASE_URL}/version',
                      json={'error': 'Internal server error'}, status=500)
        result = client.test_connection()
        assert result['status'] == 'error'


class TestCreateWorkflow:
    @responses.activate
    def test_success(self, client):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json={'id': 'wfl_001', 'workflowStatus': 'draft'}, status=200)
        result = client.create_workflow(
            user_id=USER_ID, name='Test WF',
            steps=[{'stepType': 'signature', 'recipients': [
                {'email': 'signer@example.com', 'firstName': 'Jean', 'lastName': 'Dupont'},
            ], 'maxInvites': 5}],
            metadata={'data1': 'DEM-001', 'data2': 'RH'},
        )
        assert result['workflow_id'] == 'wfl_001'
        assert result['status'] == 'draft'
        body = json.loads(responses.calls[0].request.body)
        assert body['name'] == 'Test WF'
        assert body['workflowMode'] == 'FULL'
        assert body['data1'] == 'DEM-001'

    @responses.activate
    def test_validation_error(self, client):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json={'message': 'A request field has an incorrect value.'}, status=400)
        with pytest.raises(GoodflagValidationError):
            client.create_workflow(user_id=USER_ID, name='', steps=[])

    @responses.activate
    def test_auth_error(self, client):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json={'message': 'Missing bearer token.'}, status=401)
        with pytest.raises(GoodflagAuthError):
            client.create_workflow(user_id=USER_ID, name='Test',
                                   steps=[{'stepType': 'signature', 'recipients': []}])

    def test_invalid_metadata_key(self, client):
        with pytest.raises(GoodflagValidationError, match='Invalid metadata keys'):
            client.create_workflow(
                user_id=USER_ID, name='Test',
                steps=[{'stepType': 'signature', 'recipients': []}],
                metadata={'name': 'evil', 'data1': 'ok'},
            )


class TestUploadDocument:
    @responses.activate
    def test_success(self, client):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_001/parts',
                      json={'documents': [{'id': 'doc_001'}], 'parts': []}, status=200)
        result = client.upload_document(
            workflow_id='wfl_001', file_content=b'%PDF-1.4 fake', filename='test.pdf',
            signature_profile_id='sip_Profile',
        )
        assert result['document_id'] == 'doc_001'
        sent = responses.calls[0].request
        assert 'createDocuments=true' in sent.url
        assert 'signatureProfileId=sip_Profile' in sent.url
        assert sent.headers.get('Content-Type') == 'application/pdf'
        assert 'filename="test.pdf"' in sent.headers.get('Content-Disposition', '')
        assert b'%PDF-1.4' in sent.body

    @responses.activate
    def test_base64_content(self, client):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_001/parts',
                      json={'documents': [{'id': 'doc_002'}], 'parts': []}, status=200)
        b64 = base64.b64encode(b'%PDF-1.4 content').decode()
        result = client.upload_document(workflow_id='wfl_001', file_content=b64, filename='b64.pdf')
        assert result['document_id'] == 'doc_002'

    def test_invalid_content_type(self, client):
        with pytest.raises(GoodflagValidationError, match='not allowed'):
            client.upload_document(workflow_id='wfl_001', file_content=b'<html>',
                                   filename='test.html', content_type='text/html')

    def test_file_too_large(self, client):
        with pytest.raises(GoodflagValidationError, match='too large'):
            client.upload_document(workflow_id='wfl_001',
                                   file_content=b'x' * (50 * 1024 * 1024 + 1),
                                   filename='huge.pdf')


class TestPatchWorkflowStatus:
    @responses.activate
    def test_start(self, client):
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_001',
                      json={'id': 'wfl_001', 'workflowStatus': 'started'}, status=200)
        result = client.patch_workflow_status('wfl_001', 'started')
        assert result['status'] == 'started'
        body = json.loads(responses.calls[0].request.body)
        assert body['workflowStatus'] == 'started'

    @responses.activate
    def test_stop(self, client):
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_001',
                      json={'id': 'wfl_001', 'workflowStatus': 'stopped'}, status=200)
        result = client.patch_workflow_status('wfl_001', 'stopped')
        assert result['status'] == 'stopped'

    @responses.activate
    def test_not_found(self, client):
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_bad',
                      json={'message': 'The specified workflow can not be found.'}, status=404)
        with pytest.raises(GoodflagValidationError):
            client.patch_workflow_status('wfl_bad', 'started')


class TestGetWorkflow:
    @responses.activate
    def test_success(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_001',
                      json={'id': 'wfl_001', 'workflowStatus': 'finished', 'progress': 100,
                            'data1': 'DEM-001'}, status=200)
        result = client.get_workflow('wfl_001')
        assert result['workflow_id'] == 'wfl_001'
        assert result['status'] == 'finished'
        assert result['normalized_status'] == 'finished'
        assert result['progress'] == 100

    @responses.activate
    def test_status_normalization(self, client):
        for raw, expected in [('draft', 'draft'), ('started', 'started'),
                              ('stopped', 'refused'), ('finished', 'finished'),
                              ('unknown', 'error')]:
            responses.reset()
            responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_X',
                          json={'id': 'wfl_X', 'workflowStatus': raw}, status=200)
            assert client.get_workflow('wfl_X')['normalized_status'] == expected


class TestCreateInvite:
    @responses.activate
    def test_success(self, client):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_001/invite',
                      json={'inviteUrl': 'https://goodflag.test/invite?token=eyJ'}, status=200)
        result = client.create_invite('wfl_001', 'signer@example.com')
        assert result['invite_url'].startswith('https://')
        body = json.loads(responses.calls[0].request.body)
        assert body['recipientEmail'] == 'signer@example.com'


class TestDownload:
    @responses.activate
    def test_signed_documents(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_001/downloadDocuments',
                      body=b'%PDF-1.4 signed', content_type='application/pdf',
                      headers={'Content-Disposition': 'attachment; filename="signed.pdf"'},
                      status=200)
        result = client.download('wfl_001', 'downloadDocuments', 'default')
        assert result['filename'] == 'signed.pdf'
        assert result['content_type'] == 'application/pdf'

    @responses.activate
    def test_evidence_certificate(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_001/downloadEvidenceCertificate',
                      body=b'%PDF-1.4 evidence', content_type='application/pdf',
                      headers={'Content-Disposition': 'attachment; filename="evidence.pdf"'},
                      status=200)
        result = client.download('wfl_001', 'downloadEvidenceCertificate', 'default')
        assert result['filename'] == 'evidence.pdf'

    @responses.activate
    def test_not_found(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_bad/downloadDocuments',
                      json={'message': 'The specified workflow can not be found.'}, status=404)
        with pytest.raises(GoodflagValidationError):
            client.download('wfl_bad', 'downloadDocuments', 'default')


class TestGetWebhookEvent:
    @responses.activate
    def test_success(self, client):
        responses.add(responses.GET, f'{BASE_URL}/webhookEvents/wbe_Event001',
                      json={'id': 'wbe_Event001', 'eventType': 'workflowFinished',
                            'workflowId': 'wfl_001'}, status=200)
        result = client.get_webhook_event('wbe_Event001')
        assert result['id'] == 'wbe_Event001'
        assert result['workflowId'] == 'wfl_001'


class TestSearchWorkflows:
    @responses.activate
    def test_with_text(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows',
                      json={'items': [], 'totalItems': 0}, status=200)
        client.search_workflows(text='convention')
        assert 'text=convention' in responses.calls[0].request.url


class TestNonDictErrorResponse:
    @responses.activate
    def test_string_response(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_bad',
                      json='Some error string', status=500)
        with pytest.raises(GoodflagError) as exc_info:
            client.get_workflow('wfl_bad')
        assert 'Some error string' in str(exc_info.value)

    @responses.activate
    def test_list_response(self, client):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_bad',
                      json=['error1', 'error2'], status=400)
        with pytest.raises(GoodflagValidationError):
            client.get_workflow('wfl_bad')


class TestNetworkError:
    @responses.activate
    def test_connection_error(self, client):
        responses.add(responses.GET, f'{BASE_URL}/version',
                      body=responses.ConnectionError("connection refused"))
        result = client.test_connection()
        assert result['status'] == 'error'
