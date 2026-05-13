"""Tests d'intégration du connecteur Goodflag (endpoints Passerelle)."""

import base64
import json

import pytest
import responses
from django.test import RequestFactory

from passerelle_goodflag.exceptions import GoodflagError, GoodflagValidationError
from passerelle_goodflag.models import GoodflagResource

from .conftest import (
    MOCK_INVITE_RESPONSE,
    MOCK_START_RESPONSE,
    MOCK_UPLOAD_RESPONSE,
    MOCK_VERSION_RESPONSE,
    MOCK_WEBHOOK_EVENT,
    MOCK_WORKFLOW_DETAIL,
    MOCK_WORKFLOW_LIST,
    MOCK_WORKFLOW_RESPONSE,
)

pytestmark = pytest.mark.django_db

BASE_URL = 'https://api.goodflag.test/api'
USER_ID = 'usr_TestUser123'


@pytest.fixture
def factory():
    return RequestFactory()


def _json_post(factory, path, payload):
    return factory.post(path, data=json.dumps(payload), content_type='application/json')


class TestConnectorBasics:
    def test_create_connector(self, connector):
        assert connector.pk is not None
        assert connector.base_url == BASE_URL
        assert connector.user_id == USER_ID

    def test_get_client(self, connector):
        client = connector._get_client()
        assert client.base_url == BASE_URL
        assert client.timeout == 10

    @responses.activate
    def test_check_status_ok(self, connector):
        responses.add(responses.GET, f'{BASE_URL}/version',
                      json=MOCK_VERSION_RESPONSE, status=200)
        connector.check_status()  # ne doit pas lever

    @responses.activate
    def test_check_status_failure(self, connector):
        responses.add(responses.GET, f'{BASE_URL}/version',
                      json={'message': 'down'}, status=500)
        with pytest.raises(GoodflagError):
            connector.check_status()


class TestCreateWorkflow:
    @responses.activate
    def test_with_steps(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        payload = {
            'name': 'Signature 2024',
            'steps': [{'stepType': 'signature', 'recipients': [
                {'email': 'jean@example.com', 'firstName': 'Jean', 'lastName': 'Dupont'},
            ], 'maxInvites': 5}],
            'metadata': {'data1': 'DEM-2024-001'},
        }
        result = connector.create_workflow(_json_post(factory, '/create-workflow', payload))
        assert result['data']['workflow_id'] == 'wfl_Test001'
        assert result['data']['status'] == 'draft'

    @responses.activate
    def test_with_recipients(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        payload = {
            'name': 'Signature simplifiée',
            'recipients': [{'email': 'signer@example.com', 'firstName': 'Jean',
                            'lastName': 'Dupont'}],
        }
        result = connector.create_workflow(_json_post(factory, '/create-workflow', payload))
        assert result['data']['workflow_id'] == 'wfl_Test001'

        body = json.loads(responses.calls[0].request.body)
        assert body['steps'][0]['recipients'][0]['consentPageId'] == 'cop_DefaultConsent'

    @responses.activate
    def test_recipient_flat_format(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        payload = {
            'name': 'Sig plate',
            'recipient_email': 'a@b.com',
            'recipient_firstname': 'Alice',
            'recipient_lastname': 'Martin',
            'recipient_phone': '+33612345678',
        }
        connector.create_workflow(_json_post(factory, '/create-workflow', payload))
        body = json.loads(responses.calls[0].request.body)
        recipient = body['steps'][0]['recipients'][0]
        assert recipient['email'] == 'a@b.com'
        assert recipient['firstName'] == 'Alice'
        assert recipient['phoneNumber'] == '+33612345678'

    @responses.activate
    def test_recipient_indexed_format(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        payload = {
            'name': 'Multi',
            'recipients_0_email': 'a@b.com',
            'recipients_0_firstname': 'Alice',
            'recipients_1_email': 'c@d.com',
            'recipients_1_firstname': 'Bob',
        }
        connector.create_workflow(_json_post(factory, '/create-workflow', payload))
        body = json.loads(responses.calls[0].request.body)
        recipients = body['steps'][0]['recipients']
        assert len(recipients) == 2
        assert recipients[0]['email'] == 'a@b.com'
        assert recipients[1]['email'] == 'c@d.com'

    def test_missing_name(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='name'):
            connector.create_workflow(_json_post(factory, '/create-workflow',
                                                 {'recipients': [{'email': 'a@b.com'}]}))

    def test_missing_recipients_and_steps(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='steps.*recipients'):
            connector.create_workflow(_json_post(factory, '/create-workflow', {'name': 'Test'}))

    def test_steps_and_recipients_exclusive(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='mutually exclusive'):
            connector.create_workflow(_json_post(factory, '/create-workflow', {
                'name': 'Test',
                'steps': [{'stepType': 'signature', 'recipients': []}],
                'recipients': [{'email': 'a@b.com'}],
            }))

    def test_invalid_json(self, connector, factory):
        request = factory.post('/create-workflow', data='not json',
                               content_type='application/json')
        with pytest.raises(GoodflagValidationError, match='Invalid JSON'):
            connector.create_workflow(request)

    @responses.activate
    def test_api_error(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json={'message': 'Unexpected error'}, status=500)
        with pytest.raises(GoodflagError):
            connector.create_workflow(_json_post(factory, '/create-workflow', {
                'name': 'Test', 'recipients': [{'email': 'a@b.com'}],
            }))


class TestUploadDocument:
    @responses.activate
    def test_with_base64(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/parts',
                      json=MOCK_UPLOAD_RESPONSE, status=200)
        b64 = base64.b64encode(b'%PDF-1.4 content').decode()
        result = connector.upload_document(_json_post(factory, '/upload-document', {
            'workflow_id': 'wfl_Test001',
            'file_base64': b64,
            'filename': 'test.pdf',
        }))
        assert result['data']['document_id'] == 'doc_Doc001'

    @responses.activate
    def test_with_file_object(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/parts',
                      json=MOCK_UPLOAD_RESPONSE, status=200)
        b64 = base64.b64encode(b'%PDF-1.4 content').decode()
        result = connector.upload_document(_json_post(factory, '/upload-document', {
            'workflow_id': 'wfl_Test001',
            'file': {'filename': 'doc.pdf', 'content_type': 'application/pdf', 'content': b64},
        }))
        assert result['data']['document_id'] == 'doc_Doc001'

    def test_missing_workflow(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='workflow_id'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'file_base64': base64.b64encode(b'%PDF-1.4').decode(),
            }))

    def test_missing_file(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='file'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'workflow_id': 'wfl_Test001',
            }))

    def test_invalid_pdf(self, connector, factory):
        b64 = base64.b64encode(b'<html>not a pdf</html>').decode()
        with pytest.raises(GoodflagValidationError, match='PDF'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'workflow_id': 'wfl_Test001', 'file_base64': b64,
            }))

    @responses.activate
    def test_with_file_url(self, connector, factory, monkeypatch):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/parts',
                      json=MOCK_UPLOAD_RESPONSE, status=200)

        class FakeResponse:
            status_code = 200
            content = b'%PDF-1.4 from url'

        def fake_get(url, *args, **kwargs):
            return FakeResponse()

        monkeypatch.setattr(connector.requests, 'get', fake_get)
        result = connector.upload_document(_json_post(factory, '/upload-document', {
            'workflow_id': 'wfl_Test001',
            'file_url': 'https://wcs.example.com/document.pdf',
        }))
        assert result['data']['document_id'] == 'doc_Doc001'

    def test_file_url_blocked_http(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='https'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'workflow_id': 'wfl_Test001',
                'file_url': 'http://example.com/doc.pdf',
            }))

    def test_file_url_blocked_localhost(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='local'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'workflow_id': 'wfl_Test001',
                'file_url': 'https://localhost/doc.pdf',
            }))

    def test_file_url_blocked_private_ip(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='non-routable'):
            connector.upload_document(_json_post(factory, '/upload-document', {
                'workflow_id': 'wfl_Test001',
                'file_url': 'https://192.168.1.1/doc.pdf',
            }))


class TestStartStopWorkflow:
    @responses.activate
    def test_start(self, connector, factory):
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_Test001',
                      json=MOCK_START_RESPONSE, status=200)
        result = connector.start_workflow(_json_post(factory, '/start-workflow', {
            'workflow_id': 'wfl_Test001',
        }))
        assert result['data']['status'] == 'started'

    @responses.activate
    def test_stop(self, connector, factory):
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_Test001',
                      json={'id': 'wfl_Test001', 'workflowStatus': 'stopped'}, status=200)
        result = connector.stop_workflow(factory.post('/stop-workflow'), workflow_id='wfl_Test001')
        assert result['data']['status'] == 'stopped'

    def test_start_missing_id(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='workflow_id'):
            connector.start_workflow(_json_post(factory, '/start-workflow', {}))


class TestGetWorkflow:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001',
                      json=MOCK_WORKFLOW_DETAIL, status=200)
        result = connector.get_workflow(factory.get('/get-workflow'), workflow_id='wfl_Test001')
        assert result['data']['workflow_id'] == 'wfl_Test001'
        assert result['data']['status'] == 'started'


class TestSyncStatus:
    @responses.activate
    def test_finished(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001',
                      json={'id': 'wfl_Test001', 'workflowStatus': 'finished',
                            'progress': 100}, status=200)
        result = connector.sync_status(factory.get('/sync-status'), workflow_id='wfl_Test001')
        assert result['data']['status'] == 'finished'
        assert result['data']['is_final'] is True

    @responses.activate
    def test_started_not_final(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001',
                      json={'id': 'wfl_Test001', 'workflowStatus': 'started',
                            'progress': 50}, status=200)
        result = connector.sync_status(factory.get('/sync-status'), workflow_id='wfl_Test001')
        assert result['data']['status'] == 'started'
        assert result['data']['is_final'] is False


class TestSubmitWorkflow:
    @responses.activate
    def test_full_pipeline(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/parts',
                      json=MOCK_UPLOAD_RESPONSE, status=200)
        responses.add(responses.PATCH, f'{BASE_URL}/workflows/wfl_Test001',
                      json=MOCK_START_RESPONSE, status=200)
        b64 = base64.b64encode(b'%PDF-1.4 content').decode()
        result = connector.submit_workflow(_json_post(factory, '/submit-workflow', {
            'name': 'End-to-end',
            'recipients': [{'email': 'a@b.com', 'firstName': 'A', 'lastName': 'B'}],
            'file_base64': b64,
            'filename': 'doc.pdf',
        }))
        data = result['data']
        assert data['workflow_id'] == 'wfl_Test001'
        assert data['status'] == 'started'
        assert data['document_id'] == 'doc_Doc001'


class TestCreateInvite:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/invite',
                      json=MOCK_INVITE_RESPONSE, status=200)
        result = connector.create_invite(_json_post(factory, '/create-invite', {
            'workflow_id': 'wfl_Test001',
            'recipient_email': 'signer@example.com',
        }))
        assert result['data']['invite_url'].startswith('https://')

    def test_missing_email(self, connector, factory):
        with pytest.raises(GoodflagValidationError, match='recipient_email'):
            connector.create_invite(_json_post(factory, '/create-invite', {
                'workflow_id': 'wfl_Test001',
            }))


class TestDownload:
    @responses.activate
    def test_signed_documents(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001/downloadDocuments',
                      body=b'%PDF-1.4 signed', content_type='application/pdf',
                      headers={'Content-Disposition': 'attachment; filename="signed.pdf"'},
                      status=200)
        response = connector.download_signed_documents(factory.get('/download-signed-documents'),
                                                      workflow_id='wfl_Test001')
        assert response['Content-Type'] == 'application/pdf'
        assert 'signed.pdf' in response['Content-Disposition']

    @responses.activate
    def test_evidence(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001/downloadEvidenceCertificate',
                      body=b'%PDF-1.4 evidence', content_type='application/pdf',
                      headers={'Content-Disposition': 'attachment; filename="evidence.pdf"'},
                      status=200)
        response = connector.download_evidence(factory.get('/download-evidence'),
                                               workflow_id='wfl_Test001')
        assert response['Content-Type'] == 'application/pdf'


class TestRetrieveByExternalRef:
    @responses.activate
    def test_found(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows',
                      json=MOCK_WORKFLOW_LIST, status=200)
        result = connector.retrieve_by_external_ref(factory.get('/retrieve-by-external-ref'),
                                                    external_ref='DEM-2024-001')
        assert result['data']['count'] == 1
        assert result['data']['results'][0]['workflow_id'] == 'wfl_Test001'

    @responses.activate
    def test_not_found(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows',
                      json={'items': [], 'totalItems': 0}, status=200)
        result = connector.retrieve_by_external_ref(factory.get('/retrieve-by-external-ref'),
                                                    external_ref='DOES-NOT-EXIST')
        assert result['data']['count'] == 0

    def test_missing(self, connector, factory):
        with pytest.raises(GoodflagValidationError):
            connector.retrieve_by_external_ref(factory.get('/retrieve-by-external-ref'),
                                               external_ref='')


class TestExternalRefResolution:
    @responses.activate
    def test_get_workflow_via_external_ref(self, connector, factory):
        responses.add(responses.GET, f'{BASE_URL}/workflows',
                      json=MOCK_WORKFLOW_LIST, status=200)
        responses.add(responses.GET, f'{BASE_URL}/workflows/wfl_Test001',
                      json=MOCK_WORKFLOW_DETAIL, status=200)
        result = connector.get_workflow(factory.get('/get-workflow?external_ref=DEM-2024-001'),
                                        external_ref='DEM-2024-001')
        assert result['data']['workflow_id'] == 'wfl_Test001'


class TestWebhook:
    def test_invalid_token(self, connector, factory):
        request = factory.post('/webhook?token=wrong', data=json.dumps({'id': 'wbe_X'}),
                               content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 403

    def test_valid_token_and_invalid_json(self, connector, factory):
        request = factory.post('/webhook?token=webhook-secret-token', data='not-json',
                               content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 400

    def test_missing_event_id(self, connector, factory):
        request = factory.post('/webhook?token=webhook-secret-token',
                               data=json.dumps({}), content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 400

    def test_valid_event(self, connector, factory):
        payload = {'id': 'wbe_Event001', 'workflowId': 'wfl_Test001',
                   'eventType': 'workflowFinished'}
        request = factory.post('/webhook?token=webhook-secret-token',
                               data=json.dumps(payload), content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 200

    @responses.activate
    def test_revalidation_without_secret(self, connector, factory):
        connector.webhook_secret = ''
        connector.save()
        responses.add(responses.GET, f'{BASE_URL}/webhookEvents/wbe_Event001',
                      json=MOCK_WEBHOOK_EVENT, status=200)
        payload = {'id': 'wbe_Event001', 'workflowId': 'wfl_Test001'}
        request = factory.post('/webhook', data=json.dumps(payload),
                               content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 200

    @responses.activate
    def test_revalidation_mismatch(self, connector, factory):
        connector.webhook_secret = ''
        connector.save()
        responses.add(responses.GET, f'{BASE_URL}/webhookEvents/wbe_Event001',
                      json={'id': 'wbe_Event001', 'workflowId': 'wfl_Other'}, status=200)
        payload = {'id': 'wbe_Event001', 'workflowId': 'wfl_Test001'}
        request = factory.post('/webhook', data=json.dumps(payload),
                               content_type='application/json')
        response = connector.webhook(request)
        assert response.status_code == 403


class TestPayloadParsing:
    @responses.activate
    def test_query_string_merge(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/workflows/wfl_Test001/parts',
                      json=MOCK_UPLOAD_RESPONSE, status=200)
        b64 = base64.b64encode(b'%PDF-1.4 content').decode()
        request = factory.post(
            f'/upload-document?workflow_id=wfl_Test001&file_base64={b64}',
            content_type='application/json',
        )
        result = connector.upload_document(request)
        assert result['data']['document_id'] == 'doc_Doc001'

    @responses.activate
    def test_strips_passerelle_auth_params(self, connector, factory):
        responses.add(responses.POST, f'{BASE_URL}/users/{USER_ID}/workflows',
                      json=MOCK_WORKFLOW_RESPONSE, status=200)
        # The auth params should never end up in the workflow payload sent to Goodflag.
        request = factory.post(
            '/create-workflow?orig=test&algo=x&signature=y',
            data=json.dumps({'name': 'Test', 'recipients': [{'email': 'a@b.com'}]}),
            content_type='application/json',
        )
        connector.create_workflow(request)
        body = json.loads(responses.calls[0].request.body)
        assert 'orig' not in body
        assert 'signature' not in body
