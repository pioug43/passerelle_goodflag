"""
Tests d'intégration du connecteur Goodflag (endpoints Passerelle).

Utilise responses pour mocker les appels HTTP vers l'API Goodflag
et django.test.RequestFactory pour simuler les requêtes Passerelle.
"""

import base64
import json

import pytest
import responses
from django.test import RequestFactory
from django.utils import timezone

from passerelle_goodflag.models import (
    GoodflagDocumentTrace,
    GoodflagResource,
    GoodflagWebhookEvent,
    GoodflagWorkflowTrace,
)

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


class TestConnectorCreation:
    def test_create_connector(self, connector):
        assert connector.pk is not None
        assert connector.title == 'Test Goodflag'
        assert connector.base_url == BASE_URL
        assert connector.user_id == USER_ID
        assert connector.timeout == 10
        assert connector.verify_ssl is True
        assert connector.sandbox_mode is True

    def test_get_client(self, connector):
        client = connector._get_client()
        assert client.base_url == BASE_URL
        assert client.access_token == 'act_test.secret_token_value'
        assert client.timeout == 10

    def test_category(self):
        assert str(GoodflagResource.category) == 'Signature électronique'


class TestCreateWorkflow:
    @responses.activate
    def test_success_with_steps(self, connector, factory):
        """Création avec format steps natif Goodflag."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        payload = {
            'name': 'Signature convention 2024',
            'steps': [{
                'stepType': 'signature',
                'recipients': [{
                    'consentPageId': 'cop_Test',
                    'email': 'jean.dupont@example.com',
                    'firstName': 'Jean',
                    'lastName': 'Dupont',
                }],
                'maxInvites': 5,
            }],
            'external_ref': 'DEM-2024-001',
            'metadata': {
                'data1': 'DEM-2024-001',
                'data2': 'RH',
            },
        }
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.create_workflow(request)
        data = result['data']

        assert data['workflow_id'] == 'wfl_Test001'
        assert data['status'] == 'draft'

        # Vérification de la trace locale
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
        )
        assert trace.external_ref == 'DEM-2024-001'
        assert trace.workflow_name == 'Signature convention 2024'
        assert trace.status == 'draft'

    @responses.activate
    def test_success_with_recipients(self, connector, factory):
        """Création avec format simplifié recipients (sans steps)."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        payload = {
            'name': 'Signature simplifiée',
            'recipients': [{
                'email': 'signer@example.com',
                'firstName': 'Jean',
                'lastName': 'Dupont',
            }],
            'external_ref': 'DEM-SIMPLE',
        }
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.create_workflow(request)
        assert result['data']['workflow_id'] == 'wfl_Test001'

        # Vérification que le consentPageId par défaut est injecté
        sent = responses.calls[0].request
        body = json.loads(sent.body)
        assert body['steps'][0]['stepType'] == 'signature'
        assert (
            body['steps'][0]['recipients'][0]['consentPageId']
            == 'cop_DefaultConsent'
        )

    def test_missing_name(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        payload = {'recipients': [{'email': 'a@b.com'}]}
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError, match='name'):
            connector.create_workflow(request)

    def test_missing_recipients_and_steps(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        payload = {'name': 'Test'}
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError, match='steps.*recipients'):
            connector.create_workflow(request)

    def test_invalid_json(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        request = factory.post(
            '/create-workflow',
            data='not json',
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError, match='Invalid JSON'):
            connector.create_workflow(request)

    @responses.activate
    def test_api_error(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagError
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json={
                'status': 500,
                'error': 'Internal Server Error',
                'message': 'Unexpected error',
            },
            status=500,
        )
        payload = {
            'name': 'Test',
            'recipients': [{'email': 'a@b.com'}],
        }
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagError):
            connector.create_workflow(request)


class TestUploadDocument:
    @responses.activate
    def test_success_base64(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        pdf_bytes = b'%PDF-1.4 test content'
        payload = {
            'workflow_id': 'wfl_Test001',
            'file_base64': base64.b64encode(pdf_bytes).decode(),
            'filename': 'convention.pdf',
            'content_type': 'application/pdf',
        }
        request = factory.post(
            '/upload-document',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.upload_document(request)
        data = result['data']
        assert data['document_id'] == 'doc_Doc001'

        # Vérification de la trace document
        doc_trace = GoodflagDocumentTrace.objects.get(
            resource=connector,
            goodflag_document_id='doc_Doc001',
        )
        assert doc_trace.filename == 'convention.pdf'
        assert doc_trace.document_type == 'sign'
        assert doc_trace.file_size == len(pdf_bytes)

    @responses.activate
    def test_success_nested_json(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        pdf_bytes = b'%PDF-1.4 test content'
        payload = {
            'workflow_id': 'wfl_Test001',
            'file': {
                'filename': 'nested.pdf',
                'content_type': 'application/pdf',
                'content': base64.b64encode(pdf_bytes).decode(),
            }
        }
        request = factory.post(
            '/upload-document',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.upload_document(request)
        assert result['data']['document_id'] == 'doc_Doc001'

    @responses.activate
    def test_success_multipart(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        from django.core.files.uploadedfile import SimpleUploadedFile
        pdf_bytes = b'%PDF-1.4 multipart content'
        uploaded_file = SimpleUploadedFile('multipart.pdf', pdf_bytes, content_type='application/pdf')

        payload = {'workflow_id': 'wfl_Test001'}
        # Simulate a multipart request with files
        request = factory.post(
            '/upload-document',
            data=payload,
        )
        request.FILES['file'] = uploaded_file

        result = connector.upload_document(request)
        assert result['data']['document_id'] == 'doc_Doc001'

        # Verify filename from multipart
        doc_trace = GoodflagDocumentTrace.objects.get(
            resource=connector,
            goodflag_document_id='doc_Doc001',
        )
        assert doc_trace.filename == 'multipart.pdf'

    def test_missing_workflow_id(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        payload = {'file_base64': 'abc', 'filename': 'test.pdf'}
        request = factory.post(
            '/upload-document',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError, match='workflow_id'):
            connector.upload_document(request)

    def test_missing_file(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        payload = {'workflow_id': 'wfl_001', 'filename': 'test.pdf'}
        request = factory.post(
            '/upload-document',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError, match='file_base64'):
            connector.upload_document(request)


class TestStartWorkflow:
    @responses.activate
    def test_success(self, connector, factory):
        # Créer d'abord une trace
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='draft',
        )

        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json=MOCK_START_RESPONSE,
            status=200,
        )
        payload = {'workflow_id': 'wfl_Test001'}
        request = factory.post(
            '/start-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.start_workflow(request)
        assert result['data']['status'] == 'started'

        # Vérification de la mise à jour de la trace
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
        )
        assert trace.status == 'started'

        # Vérification du payload envoyé
        sent = responses.calls[0].request
        body = json.loads(sent.body)
        assert body['workflowStatus'] == 'started'


class TestSubmitWorkflow:
    @responses.activate
    def test_success_with_file_url(self, connector, factory):
        """submit-workflow enchaîne create + upload + start en un appel."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        responses.add(
            responses.GET,
            'https://wcs.test/pdf/convention.pdf',
            body=b'%PDF-1.4 test content',
            status=200,
        )
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json=MOCK_START_RESPONSE,
            status=200,
        )

        payload = {
            'name': 'Signature convention 2024',
            'recipient_email': 'signer@example.com',
            'recipient_firstname': 'Jean',
            'recipient_lastname': 'Dupont',
            'external_ref': 'DEM-2024-001',
            'file_url': 'https://wcs.test/pdf/convention.pdf',
            'filename': 'convention.pdf',
        }
        request = factory.post(
            '/submit-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.submit_workflow(request)
        data = result['data']

        assert data['workflow_id'] == 'wfl_Test001'
        assert data['status'] == 'started'
        assert data['document_id'] == 'doc_Doc001'

        # 4 appels API : POST workflow, GET file_url, POST parts, PATCH start
        assert len(responses.calls) == 4

        # Trace workflow créée avec statut started
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001',
        )
        assert trace.status == 'started'
        assert trace.external_ref == 'DEM-2024-001'

        # Trace document créée
        doc = GoodflagDocumentTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001',
        )
        assert doc.filename == 'convention.pdf'

    @responses.activate
    def test_success_with_file_base64(self, connector, factory):
        """submit-workflow accepte un fichier en base64."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json=MOCK_START_RESPONSE,
            status=200,
        )

        pdf_bytes = b'%PDF-1.4 test content'
        payload = {
            'name': 'Signature convention 2024',
            'recipient_email': 'signer@example.com',
            'recipient_firstname': 'Jean',
            'recipient_lastname': 'Dupont',
            'external_ref': 'DEM-2024-001',
            'file': {
                'filename': 'convention.pdf',
                'content_type': 'application/pdf',
                'content': base64.b64encode(pdf_bytes).decode(),
            },
        }
        request = factory.post(
            '/submit-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.submit_workflow(request)
        assert result['data']['workflow_id'] == 'wfl_Test001'
        assert result['data']['status'] == 'started'

    @responses.activate
    def test_missing_file_raises(self, connector, factory):
        """submit-workflow lève une erreur si aucun fichier n'est fourni."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/{USER_ID}/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        payload = {
            'name': 'Signature convention 2024',
            'recipient_email': 'signer@example.com',
            'external_ref': 'DEM-2024-001',
        }
        request = factory.post(
            '/submit-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        from passerelle_goodflag.exceptions import GoodflagValidationError
        with pytest.raises(GoodflagValidationError):
            connector.submit_workflow(request)


class TestGetWorkflow:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json=MOCK_WORKFLOW_DETAIL,
            status=200,
        )
        request = factory.get('/get-workflow')
        result = connector.get_workflow(request, workflow_id='wfl_Test001')
        data = result['data']
        assert data['workflow_id'] == 'wfl_Test001'
        assert data['normalized_status'] == 'started'
        assert data['progress'] == 50


class TestSyncStatus:
    @responses.activate
    def test_finished(self, connector, factory):
        """sync_status retourne directement 'finished' quand Goodflag dit 'finished'."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'finished',
                'name': 'WF',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
            },
            status=200,
        )
        request = factory.get('/sync-status')
        result = connector.sync_status(request, workflow_id='wfl_Test001')
        data = result['data']
        assert data['status'] == 'finished'
        assert data['is_final'] is True
        assert data['progress'] == 100
        # La trace est mise à jour
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001')
        assert trace.status == 'finished'

    @responses.activate
    def test_started(self, connector, factory):
        """sync_status retourne 'started' quand Goodflag dit 'started'."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='draft',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'started',
                'name': 'WF',
                'progress': 50,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000300000,
            },
            status=200,
        )
        request = factory.get('/sync-status')
        result = connector.sync_status(request, workflow_id='wfl_Test001')
        data = result['data']
        assert data['status'] == 'started'
        assert data['is_final'] is False
        assert data['progress'] == 50

    @responses.activate
    def test_stopped_returns_refused(self, connector, factory):
        """sync_status normalise 'stopped' Goodflag en 'refused'."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'stopped',
                'name': 'WF',
                'progress': 0,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000300000,
                'stopped': 1700000300000,
            },
            status=200,
        )
        request = factory.get('/sync-status')
        result = connector.sync_status(request, workflow_id='wfl_Test001')
        data = result['data']
        assert data['status'] == 'refused'
        assert data['is_final'] is True

    @responses.activate
    def test_updates_trace(self, connector, factory):
        """sync_status met à jour la trace locale avec le statut normalisé."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'finished',
                'name': 'WF',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
            },
            status=200,
        )
        request = factory.get('/sync-status')
        connector.sync_status(request, workflow_id='wfl_Test001')
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001')
        assert trace.status == 'finished'


class TestCreateInvite:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/invite',
            json=MOCK_INVITE_RESPONSE,
            status=200,
        )
        payload = {
            'workflow_id': 'wfl_Test001',
            'recipient_email': 'signer@example.com',
        }
        request = factory.post(
            '/create-invite',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.create_invite(request)
        data = result['data']
        assert data['invite_url'].startswith('https://')


class TestDownloadSignedDocuments:
    @responses.activate
    def test_success(self, connector, factory):
        pdf_bytes = b'%PDF-1.4 signed document'
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001/downloadDocuments',
            body=pdf_bytes,
            content_type='application/pdf',
            headers={
                'Content-Disposition': 'attachment; filename="signed_conv.pdf"',
            },
            status=200,
        )
        request = factory.get('/download-signed-documents')
        response = connector.download_signed_documents(
            request, workflow_id='wfl_Test001'
        )
        assert response['Content-Type'] == 'application/pdf'
        assert b'signed document' in response.content

    @responses.activate
    def test_goodflag_api_error_is_propagated(self, connector, factory):
        """Si Goodflag renvoie une erreur HTTP, elle est propagée proprement."""
        from passerelle_goodflag.exceptions import GoodflagError
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001/downloadDocuments',
            json={'message': 'Workflow is not finished'},
            status=400,
        )
        request = factory.get('/download-signed-documents')
        with pytest.raises(GoodflagError):
            connector.download_signed_documents(request, workflow_id='wfl_Test001')


class TestWebhook:
    @responses.activate
    def test_nominal_with_verification(self, connector, factory):
        """Webhook avec token URL valide + re-validation API."""
        # Mock pour la vérification de l'événement webhook
        responses.add(
            responses.GET,
            f'{BASE_URL}/webhookEvents/wbe_Event001',
            json=MOCK_WEBHOOK_EVENT,
            status=200,
        )
        # Mock pour la récupération du statut workflow
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'finished',
                'name': 'WF',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
            },
            status=200,
        )

        payload = {
            'id': 'wbe_Event001',
            'eventType': 'workflowFinished',
            'workflowId': 'wfl_Test001',
            'webhookId': 'wbh_Webhook001',
            'created': 1700000500000,
            'updated': 1700000500000,
        }
        request = factory.post(
            '/webhook?token=webhook-secret-token',
            data=json.dumps(payload),
            content_type='application/json',
        )
        # Django test RequestFactory encode les query params dans META
        request.GET = {'token': 'webhook-secret-token'}
        response = connector.webhook(request)

        assert response.status_code == 200
        data = json.loads(response.content)
        assert data['status'] == 'ok'

        # Vérification de l'enregistrement
        event = GoodflagWebhookEvent.objects.get(
            resource=connector,
            event_id='wbe_Event001',
        )
        assert event.event_type == 'workflowFinished'
        assert event.goodflag_workflow_id == 'wfl_Test001'
        assert event.raw_status == 'finished'
        assert event.normalized_status == 'finished'

    @responses.activate
    def test_duplicate_event(self, connector, factory):
        """Un événement avec le même event_id ne doit pas être traité 2 fois."""
        GoodflagWebhookEvent.objects.create(
            resource=connector,
            event_id='wbe_Dup',
            event_type='workflowFinished',
            goodflag_workflow_id='wfl_001',
        )

        payload = {
            'id': 'wbe_Dup',
            'eventType': 'workflowFinished',
            'workflowId': 'wfl_001',
        }
        request = factory.post(
            '/webhook?token=webhook-secret-token',
            data=json.dumps(payload),
            content_type='application/json',
        )
        request.GET = {'token': 'webhook-secret-token'}
        response = connector.webhook(request)

        assert response.status_code == 200
        data = json.loads(response.content)
        assert data['status'] == 'already_processed'

        count = GoodflagWebhookEvent.objects.filter(
            resource=connector,
            event_id='wbe_Dup',
        ).count()
        assert count == 1

    def test_invalid_token(self, connector, factory):
        payload = {'id': 'wbe_bad', 'eventType': 'test'}
        request = factory.post(
            '/webhook?token=wrong-token',
            data=json.dumps(payload),
            content_type='application/json',
        )
        request.GET = {'token': 'wrong-token'}
        response = connector.webhook(request)
        assert response.status_code == 403

    def test_missing_token(self, connector, factory):
        payload = {'id': 'wbe_nosig', 'eventType': 'test'}
        request = factory.post(
            '/webhook',
            data=json.dumps(payload),
            content_type='application/json',
        )
        request.GET = {}
        response = connector.webhook(request)
        assert response.status_code == 403

    def test_invalid_json(self, connector, factory):
        """Webhook sans token secret pour tester le JSON invalide."""
        connector.webhook_secret = ''
        connector.save()

        request = factory.post(
            '/webhook',
            data='not json at all',
            content_type='application/json',
        )
        request.GET = {}
        response = connector.webhook(request)
        assert response.status_code == 400

    @responses.activate
    def test_webhook_updates_trace(self, connector, factory):
        """Le webhook met à jour la trace du workflow."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Traced',
            external_ref='DEM-TRACE',
            status='started',
        )

        responses.add(
            responses.GET,
            f'{BASE_URL}/webhookEvents/wbe_TraceUpdate',
            json={
                'id': 'wbe_TraceUpdate',
                'eventType': 'workflowFinished',
                'workflowId': 'wfl_Traced',
                'webhookId': 'wbh_001',
                'created': 1700000500000,
                'updated': 1700000500000,
            },
            status=200,
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Traced',
            json={
                'id': 'wfl_Traced',
                'workflowStatus': 'finished',
                'name': 'WF',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
            },
            status=200,
        )

        payload = {
            'id': 'wbe_TraceUpdate',
            'eventType': 'workflowFinished',
            'workflowId': 'wfl_Traced',
            'webhookId': 'wbh_001',
            'created': 1700000500000,
        }
        request = factory.post(
            '/webhook?token=webhook-secret-token',
            data=json.dumps(payload),
            content_type='application/json',
        )
        request.GET = {'token': 'webhook-secret-token'}
        response = connector.webhook(request)
        assert response.status_code == 200

        trace = GoodflagWorkflowTrace.objects.get(
            goodflag_workflow_id='wfl_Traced'
        )
        assert trace.status == 'finished'


class TestRetrieveByExternalRef:
    def test_found(self, connector, factory):
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Ext001',
            external_ref='DEM-2024-099',
            workflow_name='Convention RH',
            status='started',
        )
        request = factory.get('/retrieve-by-external-ref')
        result = connector.retrieve_by_external_ref(
            request, external_ref='DEM-2024-099'
        )
        data = result['data']
        assert data['count'] == 1
        assert data['results'][0]['workflow_id'] == 'wfl_Ext001'

    def test_not_found(self, connector, factory):
        request = factory.get('/retrieve-by-external-ref')
        result = connector.retrieve_by_external_ref(
            request, external_ref='UNKNOWN'
        )
        assert result['data']['count'] == 0

    def test_missing_ref(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        request = factory.get('/retrieve-by-external-ref')
        with pytest.raises(GoodflagValidationError, match='external_ref'):
            connector.retrieve_by_external_ref(request, external_ref='')


class TestSecretMasking:
    """Vérifie que les secrets ne fuient pas dans les logs."""

    def test_sanitize_hides_token(self):
        from passerelle_goodflag.client import _sanitize_for_log
        data = {
            'access_token': 'my-secret-token',
            'Authorization': 'Bearer xyz',
            'password': 'p4ss',
            'safe_field': 'visible',
        }
        result = _sanitize_for_log(data)
        assert result['access_token'] == '***MASKED***'
        assert result['password'] == '***MASKED***'
        assert result['safe_field'] == 'visible'

    def test_connector_token_not_in_repr(self, connector):
        """Le token ne doit pas apparaître dans __str__ du connecteur."""
        text = str(connector)
        assert 'act_test.secret_token_value' not in text


class TestStopWorkflow:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={'id': 'wfl_Test001', 'workflowStatus': 'stopped'},
            status=200,
        )
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='started',
        )
        payload = {'workflow_id': 'wfl_Test001'}
        request = factory.post(
            '/stop-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.stop_workflow(request)
        assert result['data']['status'] == 'stopped'
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001'
        )
        assert trace.status == 'stopped'


class TestArchiveWorkflow:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.PATCH,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={'id': 'wfl_Test001', 'workflowStatus': 'archived'},
            status=200,
        )
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='finished',
        )
        payload = {'workflow_id': 'wfl_Test001'}
        request = factory.post(
            '/archive-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.archive_workflow(request)
        assert result['data']['status'] == 'archived'
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001'
        )
        assert trace.status == 'archived'


class TestUploadDocuments:
    """Tests de l'endpoint upload-documents (multi-fichiers)."""

    @responses.activate
    def test_success_multi(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/parts',
            json=MOCK_UPLOAD_RESPONSE,
            status=200,
        )
        import io
        content = b'%PDF-1.4 fake pdf content'
        fake_file = io.BytesIO(content)
        from django.core.files.uploadedfile import SimpleUploadedFile
        uploaded = SimpleUploadedFile('doc.pdf', content, content_type='application/pdf')
        request = factory.post(
            '/upload-documents',
            data={'workflow_id': 'wfl_Test001', 'file_0': uploaded},
            format='multipart',
        )
        result = connector.upload_documents(request)
        assert 'data' in result


class TestGetViewerUrl:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/documents/doc_Doc001/viewer',
            json={'viewerUrl': 'https://viewer.example.com/token123'},
            status=200,
        )
        payload = {'document_id': 'doc_Doc001'}
        request = factory.post(
            '/get-viewer-url',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.get_viewer_url(request)
        assert 'data' in result
        assert 'viewer_url' in result['data']


class TestDownloadEvidence:
    @responses.activate
    def test_success_with_workflow_id(self, connector, factory):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001/downloadEvidenceCertificate',
            body=b'%PDF-1.4 evidence content',
            headers={
                'Content-Type': 'application/pdf',
                'Content-Disposition': 'attachment; filename="evidence.pdf"',
            },
            status=200,
        )
        request = factory.get(
            '/download-evidence',
            data={'workflow_id': 'wfl_Test001'},
        )
        result = connector.download_evidence(request, workflow_id='wfl_Test001')
        assert result.status_code == 200

    @responses.activate
    def test_success_with_external_ref(self, connector, factory):
        """Fallback via external_ref si workflow_id absent."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='finished',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001/downloadEvidenceCertificate',
            body=b'%PDF-1.4 evidence content',
            headers={
                'Content-Type': 'application/pdf',
                'Content-Disposition': 'attachment; filename="evidence.pdf"',
            },
            status=200,
        )
        request = factory.get(
            '/download-evidence',
            data={'external_ref': 'DEM-001'},
        )
        result = connector.download_evidence(request)
        assert result.status_code == 200


class TestResendInvite:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.POST,
            f'{BASE_URL}/workflows/wfl_Test001/sendInvite',
            json={'inviteUrl': 'https://sign.example.com/invite/abc'},
            status=200,
        )
        payload = {
            'workflow_id': 'wfl_Test001',
            'recipient_email': 'signer@example.com',
        }
        request = factory.post(
            '/resend-invite',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.resend_invite(request)
        assert 'data' in result
        assert result['data']['invite_url'] == 'https://sign.example.com/invite/abc'

    def test_missing_recipient_email(self, connector, factory):
        from passerelle_goodflag.exceptions import GoodflagValidationError
        payload = {'workflow_id': 'wfl_Test001'}
        request = factory.post(
            '/resend-invite',
            data=json.dumps(payload),
            content_type='application/json',
        )
        with pytest.raises(GoodflagValidationError):
            connector.resend_invite(request)


class TestListWorkflows:
    @responses.activate
    def test_success(self, connector, factory):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows',
            json=MOCK_WORKFLOW_LIST,
            status=200,
        )
        request = factory.get('/list-workflows')
        result = connector.list_workflows(request)
        assert 'data' in result
        assert 'total' in result['data']
        assert 'items' in result['data']

    @responses.activate
    def test_with_filters(self, connector, factory):
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows',
            json=MOCK_WORKFLOW_LIST,
            status=200,
        )
        request = factory.get(
            '/list-workflows',
            data={'status': 'started', 'per_page': '10', 'page': '0'},
        )
        result = connector.list_workflows(request)
        assert result['data']['per_page'] == 10


class TestMultiRecipients:
    @responses.activate
    def test_numbered_format(self, connector, factory):
        """Test du format multi-signataires indexé (recipients_0_email, ...)."""
        responses.add(
            responses.POST,
            f'{BASE_URL}/users/usr_Test001/workflows',
            json=MOCK_WORKFLOW_RESPONSE,
            status=200,
        )
        payload = {
            'name': 'Workflow multi-sign',
            'recipients_0_email': 'alice@example.com',
            'recipients_0_firstname': 'Alice',
            'recipients_0_lastname': 'Martin',
            'recipients_1_email': 'bob@example.com',
            'recipients_1_firstname': 'Bob',
            'recipients_1_lastname': 'Dupont',
            'external_ref': 'DEM-002',
        }
        request = factory.post(
            '/create-workflow',
            data=json.dumps(payload),
            content_type='application/json',
        )
        result = connector.create_workflow(request)
        assert result['data']['workflow_id'] == 'wfl_Test001'
        # Vérifier que les steps envoyés à Goodflag contiennent 2 recipients
        sent_body = json.loads(responses.calls[0].request.body)
        recipients_in_step = sent_body['steps'][0]['recipients']
        assert len(recipients_in_step) == 2
        assert recipients_in_step[0]['email'] == 'alice@example.com'
        assert recipients_in_step[1]['email'] == 'bob@example.com'


class TestCheckStatus:
    @responses.activate
    def test_success(self, connector):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            json='sgs-wm-webapp:1.19.4-RC1',
            status=200,
        )
        # check_status ne doit pas lever d'exception
        connector.check_status()

    @responses.activate
    def test_failure_raises(self, connector):
        responses.add(
            responses.GET,
            f'{BASE_URL}/version',
            json={'error': 'Service unavailable'},
            status=503,
        )
        with pytest.raises(Exception):
            connector.check_status()


class TestHourly:
    @responses.activate
    def test_syncs_active_workflows(self, connector):
        """
        hourly() met à jour la trace quand workflowStatus change.
        Quand Goodflag retourne workflowStatus='finished', la trace
        doit passer à 'finished' (statut normalisé).
        """
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Test001',
            external_ref='DEM-001',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Test001',
            json={
                'id': 'wfl_Test001',
                'workflowStatus': 'finished',
                'name': 'WF',
                'progress': 100,
                'steps': [],
                'currentRecipientEmails': [],
                'currentRecipientUsers': [],
                'created': 1700000000000,
                'updated': 1700000500000,
                'finished': 1700000500000,
            },
            status=200,
        )
        connector.hourly()
        trace = GoodflagWorkflowTrace.objects.get(
            resource=connector, goodflag_workflow_id='wfl_Test001'
        )
        assert trace.status == 'finished'

    def test_no_active_workflows(self, connector):
        """hourly() ne fait rien s'il n'y a pas de workflows actifs."""
        connector.hourly()  # ne doit pas lever d'exception


class TestDaily:
    def test_purge_old_traces(self, connector):
        from datetime import timedelta
        old_date = timezone.now() - timedelta(days=200)
        trace = GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Old001',
            external_ref='DEM-OLD',
            status='finished',
        )
        # Forcer une date ancienne
        GoodflagWorkflowTrace.objects.filter(pk=trace.pk).update(
            created_at=old_date
        )
        connector.daily()
        assert not GoodflagWorkflowTrace.objects.filter(pk=trace.pk).exists()

    def test_keeps_recent_traces(self, connector):
        trace = GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Recent001',
            external_ref='DEM-RECENT',
            status='started',
        )
        connector.daily()
        assert GoodflagWorkflowTrace.objects.filter(pk=trace.pk).exists()


class TestValidateFileContent:
    def test_valid_pdf_passes(self):
        from passerelle_goodflag.models import _validate_file_content
        _validate_file_content(b'%PDF-1.4 valid content', 'application/pdf')

    def test_invalid_pdf_raises(self):
        from passerelle_goodflag.models import _validate_file_content
        from passerelle_goodflag.exceptions import GoodflagValidationError
        with pytest.raises(GoodflagValidationError, match='%PDF'):
            _validate_file_content(b'not a pdf', 'application/pdf')

    def test_encrypted_pdf_raises(self):
        from passerelle_goodflag.models import _validate_file_content
        from passerelle_goodflag.exceptions import GoodflagValidationError
        encrypted = b'%PDF-1.4 ' + b'/Encrypt some content'
        with pytest.raises(GoodflagValidationError, match='chiffrement'):
            _validate_file_content(encrypted, 'application/pdf')

    def test_empty_file_raises(self):
        from passerelle_goodflag.models import _validate_file_content
        from passerelle_goodflag.exceptions import GoodflagValidationError
        with pytest.raises(GoodflagValidationError, match='vide'):
            _validate_file_content(b'', 'application/pdf')


class TestWcsCallback:
    """Tests de la notification WCS via _notify_wcs() (callback global publik_callback_url)."""

    @responses.activate
    def test_webhook_triggers_wcs_callback(self, connector, factory):
        """Le webhook workflowFinished utilise le publik_callback_url global."""
        connector.publik_callback_url = 'https://wcs.test/api/global-hook/'
        connector.save()
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_Cb001',
            external_ref='DEM-CB-001',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/webhookEvents/wbe_CbEvt',
            json={
                'id': 'wbe_CbEvt', 'eventType': 'workflowFinished',
                'workflowId': 'wfl_Cb001', 'webhookId': 'wbh_001',
                'created': 1700000500000, 'updated': 1700000500000,
            },
            status=200,
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_Cb001',
            json={
                'id': 'wfl_Cb001', 'workflowStatus': 'finished', 'name': 'WF',
                'progress': 100, 'steps': [], 'currentRecipientEmails': [],
                'currentRecipientUsers': [], 'created': 1700000000000,
                'updated': 1700000500000, 'finished': 1700000500000,
            },
            status=200,
        )

        from unittest.mock import MagicMock, patch
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests = MagicMock()
        mock_requests.post.return_value = mock_response

        payload = {
            'id': 'wbe_CbEvt', 'eventType': 'workflowFinished',
            'workflowId': 'wfl_Cb001', 'webhookId': 'wbh_001',
            'created': 1700000500000,
        }
        request = factory.post(
            '/webhook?token=webhook-secret-token',
            data=json.dumps(payload),
            content_type='application/json',
        )
        request.GET = {'token': 'webhook-secret-token'}

        with patch.object(connector, 'requests', mock_requests):
            response = connector.webhook(request)

        assert response.status_code == 200
        mock_requests.post.assert_called_once()
        call_args = mock_requests.post.call_args
        assert call_args[0][0] == 'https://wcs.test/api/global-hook/'
        assert call_args[1]['json']['status'] == 'finished'

    @responses.activate
    def test_hourly_triggers_callback_on_finished(self, connector):
        """hourly() notifie WCS quand un workflow passe à finished."""
        connector.publik_callback_url = 'https://wcs.test/api/forms/conv/99/hooks/sig-done/'
        connector.save()
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_HourlyCb',
            external_ref='DEM-HOURLY',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_HourlyCb',
            json={
                'id': 'wfl_HourlyCb', 'workflowStatus': 'finished', 'name': 'WF',
                'progress': 100, 'steps': [], 'currentRecipientEmails': [],
                'currentRecipientUsers': [], 'created': 1700000000000,
                'updated': 1700000500000, 'finished': 1700000500000,
            },
            status=200,
        )

        from unittest.mock import MagicMock, patch
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests = MagicMock()
        mock_requests.post.return_value = mock_response

        with patch.object(connector, 'requests', mock_requests):
            connector.hourly()

        trace = GoodflagWorkflowTrace.objects.get(goodflag_workflow_id='wfl_HourlyCb')
        assert trace.status == 'finished'
        mock_requests.post.assert_called_once()
        assert mock_requests.post.call_args[1]['json']['event_type'] == 'workflowFinished'

    @responses.activate
    def test_hourly_no_callback_when_still_started(self, connector):
        """hourly() ne notifie pas WCS si le workflow reste en started."""
        GoodflagWorkflowTrace.objects.create(
            resource=connector,
            goodflag_workflow_id='wfl_StillStarted',
            status='started',
        )
        responses.add(
            responses.GET,
            f'{BASE_URL}/workflows/wfl_StillStarted',
            json={
                'id': 'wfl_StillStarted', 'workflowStatus': 'started', 'name': 'WF',
                'progress': 50, 'steps': [], 'currentRecipientEmails': [],
                'currentRecipientUsers': [], 'created': 1700000000000,
                'updated': 1700000300000,
            },
            status=200,
        )

        from unittest.mock import MagicMock, patch
        mock_requests = MagicMock()

        with patch.object(connector, 'requests', mock_requests):
            connector.hourly()

        mock_requests.post.assert_not_called()

