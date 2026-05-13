"""Fixtures pytest pour les tests du connecteur Goodflag."""

import pytest

from passerelle_goodflag.models import GoodflagResource


@pytest.fixture
def connector(db):
    return GoodflagResource.objects.create(
        title='Test Goodflag',
        slug='test-goodflag',
        description='Connecteur Goodflag de test',
        base_url='https://api.goodflag.test/api',
        access_token='act_test.secret_token_value',
        user_id='usr_TestUser123',
        timeout=10,
        verify_ssl=True,
        default_consent_page_id='cop_DefaultConsent',
        default_signature_profile_id='sip_DefaultProfile',
        default_layout_id='lay_DefaultLayout',
    )


MOCK_WORKFLOW_RESPONSE = {
    'id': 'wfl_Test001',
    'workflowStatus': 'draft',
    'name': 'Test Workflow',
}

MOCK_WORKFLOW_DETAIL = {
    'id': 'wfl_Test001',
    'workflowStatus': 'started',
    'name': 'Test Workflow',
    'progress': 50,
    'steps': [],
}

MOCK_UPLOAD_RESPONSE = {
    'documents': [{'id': 'doc_Doc001'}],
    'parts': [{'filename': 'convention.pdf', 'contentType': 'application/pdf', 'size': 100}],
}

MOCK_START_RESPONSE = {
    'id': 'wfl_Test001',
    'workflowStatus': 'started',
}

MOCK_VERSION_RESPONSE = 'sgs-wm-webapp:1.19.4-RC1'

MOCK_WORKFLOW_LIST = {
    'items': [{'id': 'wfl_Test001', 'name': 'Test', 'workflowStatus': 'draft',
               'data1': 'DEM-2024-001'}],
    'totalItems': 1,
}

MOCK_INVITE_RESPONSE = {'inviteUrl': 'https://goodflag.test/invite?token=eyJtest123'}

MOCK_VIEWER_RESPONSE = {
    'viewerUrl': 'https://goodflag.test/viewer?token=eyJview123',
    'expired': '2030-01-01T00:00:00Z',
}
