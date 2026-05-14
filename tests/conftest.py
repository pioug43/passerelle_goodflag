import pytest

from passerelle_goodflag.models import GoodflagResource


@pytest.fixture
def connector(db):
    return GoodflagResource.objects.create(
        title='Test Goodflag', slug='test-goodflag', description='',
        base_url='https://api.goodflag.test/api',
        access_token='act_test.secret',
        user_id='usr_TestUser123',
        default_consent_page_id='cop_Default',
        default_signature_profile_id='sip_Default',
    )


WF = {'id': 'wfl_Test001', 'workflowStatus': 'draft', 'name': 'Test'}
WF_STARTED = {'id': 'wfl_Test001', 'workflowStatus': 'started', 'progress': 50}
UPLOAD = {'documents': [{'id': 'doc_Doc001'}], 'parts': []}
INVITE = {'inviteUrl': 'https://goodflag.test/invite?t=eyJ'}
VIEWER = {'viewerUrl': 'https://goodflag.test/viewer?t=eyJ'}
WF_LIST = {'items': [{'id': 'wfl_Test001', 'name': 'T', 'workflowStatus': 'draft',
                      'data1': 'DEM-2024-001'}], 'totalItems': 1}
WF_MULTI = {'id': 'wfl_Multi001', 'workflowStatus': 'draft', 'name': 'Multi-step'}
WF_MULTI_STARTED = {'id': 'wfl_Multi001', 'workflowStatus': 'started', 'progress': 0}
UPLOAD_MULTI = {'documents': [{'id': 'doc_Multi001'}], 'parts': []}
