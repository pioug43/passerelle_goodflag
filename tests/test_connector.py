"""Tests d'intégration minimaux du connecteur Goodflag."""

import base64
import json

import pytest
import responses
from django.test import RequestFactory

from passerelle_goodflag.exceptions import GoodflagError, GoodflagValidationError

from .conftest import (
    INVITE, UPLOAD, UPLOAD_MULTI, VIEWER, WF, WF_LIST, WF_MULTI, WF_MULTI_STARTED, WF_STARTED,
)

pytestmark = pytest.mark.django_db
BASE = 'https://api.goodflag.test/api'


@pytest.fixture
def factory():
    return RequestFactory()


def _post(factory, payload):
    return factory.post('/x', data=json.dumps(payload), content_type='application/json')


@responses.activate
def test_check_status(connector):
    responses.add(responses.GET, f'{BASE}/version', json='sgs:1.0', status=200)
    connector.check_status()  # ne doit pas lever
    responses.reset()
    responses.add(responses.GET, f'{BASE}/version', json={}, status=500)
    with pytest.raises(GoodflagError):
        connector.check_status()


@responses.activate
def test_create_workflow(connector, factory):
    responses.add(responses.POST, f'{BASE}/users/usr_TestUser123/workflows', json=WF, status=200)
    result = connector.create_workflow(_post(factory, {
        'name': 'Sig 2024',
        'recipient_email': 'a@b.com', 'recipient_firstname': 'A', 'recipient_lastname': 'B',
        'metadata': {'data1': 'DEM-2024-001'},
    }))
    assert result['data']['workflow_id'] == 'wfl_Test001'
    body = json.loads(responses.calls[0].request.body)
    assert body['steps'][0]['recipients'][0]['consentPageId'] == 'cop_Default'
    assert body['data1'] == 'DEM-2024-001'


def test_create_workflow_validation(connector, factory):
    with pytest.raises(GoodflagValidationError, match='name'):
        connector.create_workflow(_post(factory, {'recipients': [{'email': 'a@b.com'}]}))
    with pytest.raises(GoodflagValidationError, match='steps.*recipients'):
        connector.create_workflow(_post(factory, {
            'name': 'T', 'steps': [{}], 'recipients': [{'email': 'a@b.com'}],
        }))


def test_create_workflow_invalid_metadata(connector, factory):
    with pytest.raises(GoodflagValidationError, match='metadata'):
        connector.create_workflow(_post(factory, {
            'name': 'T', 'recipients': [{'email': 'a@b.com'}],
            'metadata': {'name': 'evil'},
        }))


@responses.activate
def test_submit_workflow_end_to_end(connector, factory):
    responses.add(responses.POST, f'{BASE}/users/usr_TestUser123/workflows', json=WF, status=200)
    responses.add(responses.POST, f'{BASE}/workflows/wfl_Test001/parts', json=UPLOAD, status=200)
    responses.add(responses.PATCH, f'{BASE}/workflows/wfl_Test001',
                  json={'id': 'wfl_Test001', 'workflowStatus': 'started'}, status=200)
    b64 = base64.b64encode(b'%PDF-1.4 content').decode()
    result = connector.submit_workflow(_post(factory, {
        'name': 'E2E',
        'recipients': [{'email': 'a@b.com', 'firstName': 'A', 'lastName': 'B'}],
        'file_base64': b64, 'filename': 'doc.pdf',
    }))
    assert result['data']['workflow_id'] == 'wfl_Test001'
    assert result['data']['status'] == 'started'
    assert result['data']['document_id'] == 'doc_Doc001'


@responses.activate
def test_upload_document(connector, factory):
    responses.add(responses.POST, f'{BASE}/workflows/wfl_Test001/parts', json=UPLOAD, status=200)
    b64 = base64.b64encode(b'%PDF-1.4 content').decode()
    result = connector.upload_document(_post(factory, {
        'workflow_id': 'wfl_Test001', 'file_base64': b64, 'filename': 'doc.pdf',
    }))
    assert result['data']['document_id'] == 'doc_Doc001'


def test_upload_document_ssrf(connector, factory):
    for url in ('http://example.com/doc.pdf', 'https://localhost/doc.pdf',
                'https://192.168.1.1/doc.pdf'):
        with pytest.raises(GoodflagValidationError):
            connector.upload_document(_post(factory, {
                'workflow_id': 'wfl_Test001', 'file_url': url,
            }))


@responses.activate
def test_start_stop_workflow(connector, factory):
    responses.add(responses.PATCH, f'{BASE}/workflows/wfl_Test001', json=WF_STARTED, status=200)
    assert connector.start_workflow(_post(factory, {'workflow_id': 'wfl_Test001'})
                                    )['data']['status'] == 'started'
    responses.reset()
    responses.add(responses.PATCH, f'{BASE}/workflows/wfl_Test001',
                  json={'id': 'wfl_Test001', 'workflowStatus': 'stopped'}, status=200)
    assert connector.stop_workflow(factory.post('/x'), workflow_id='wfl_Test001'
                                   )['data']['status'] == 'stopped'


@responses.activate
def test_sync_status_normalization(connector, factory):
    for raw, normalized, is_final in [('finished', 'finished', True),
                                      ('archived', 'finished', True),
                                      ('started', 'started', False),
                                      ('stopped', 'refused', True)]:
        responses.reset()
        responses.add(responses.GET, f'{BASE}/workflows/wfl_Test001',
                      json={'id': 'wfl_Test001', 'workflowStatus': raw}, status=200)
        result = connector.sync_status(factory.get('/x'), workflow_id='wfl_Test001')
        assert result['data']['status'] == normalized
        assert result['data']['is_final'] is is_final


def test_upload_document_file_url_size_limit(connector, factory, monkeypatch):
    from passerelle_goodflag.client import MAX_UPLOAD_SIZE

    class OversizedResponse:
        status_code = 200

        def iter_content(self, chunk_size):
            yield b'%PDF-1.4 '
            sent = 0
            while sent <= MAX_UPLOAD_SIZE:
                blob = b'\0' * chunk_size
                yield blob
                sent += len(blob)

        def close(self):
            pass

    monkeypatch.setattr(connector.requests, 'get',
                        lambda *a, **kw: OversizedResponse())
    with pytest.raises(GoodflagValidationError, match='exceeds maximum'):
        connector.upload_document(_post(factory, {
            'workflow_id': 'wfl_Test001',
            'file_url': 'https://wcs.example.com/huge.pdf',
        }))


@responses.activate
def test_resend_invite(connector, factory):
    responses.add(responses.POST, f'{BASE}/workflows/wfl_Test001/sendInvite',
                  json=INVITE, status=200)
    result = connector.resend_invite(_post(factory, {
        'workflow_id': 'wfl_Test001', 'recipient_email': 'signer@example.com',
    }))
    assert result['data']['invite_url'].startswith('https://')
    with pytest.raises(GoodflagValidationError, match='recipient_email'):
        connector.resend_invite(_post(factory, {'workflow_id': 'wfl_Test001'}))


@responses.activate
def test_get_viewer_url(connector, factory):
    responses.add(responses.POST, f'{BASE}/documents/doc_Doc001/viewer',
                  json=VIEWER, status=200)
    result = connector.get_viewer_url(_post(factory, {'document_id': 'doc_Doc001'}))
    assert result['data']['viewer_url'].startswith('https://')


@responses.activate
def test_list_workflows(connector, factory):
    responses.add(responses.GET, f'{BASE}/workflows', json=WF_LIST, status=200)
    result = connector.list_workflows(factory.get('/x?text=DEM&page=0&per_page=10'))
    assert result['data']['total'] == 1
    assert result['data']['items'][0]['workflow_id'] == 'wfl_Test001'


@responses.activate
def test_download_signed_documents(connector, factory):
    responses.add(responses.GET, f'{BASE}/workflows/wfl_Test001/downloadDocuments',
                  body=b'%PDF-1.4 signed', content_type='application/pdf',
                  headers={'Content-Disposition': 'attachment; filename="signed.pdf"'},
                  status=200)
    response = connector.download_signed_documents(factory.get('/x'), workflow_id='wfl_Test001')
    assert response['Content-Type'] == 'application/pdf'
    assert 'signed.pdf' in response['Content-Disposition']


@responses.activate
def test_external_ref_resolution(connector, factory):
    responses.add(responses.GET, f'{BASE}/workflows', json=WF_LIST, status=200)
    responses.add(responses.GET, f'{BASE}/workflows/wfl_Test001', json=WF_STARTED, status=200)
    result = connector.get_workflow(factory.get('/x?external_ref=DEM-2024-001'),
                                    external_ref='DEM-2024-001')
    assert result['data']['workflow_id'] == 'wfl_Test001'
