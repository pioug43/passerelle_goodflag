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
        webhook_secret='webhook-secret-token',
        tenant_id='ten_TestTenant',
        debug_mode=True,
        sandbox_mode=True,
    )


MOCK_WORKFLOW_RESPONSE = {
    'id': 'wfl_Test001',
    'workflowStatus': 'draft',
    'name': 'Test Workflow',
    'workflowMode': 'FULL',
    'progress': 0,
    'steps': [
        {
            'id': 'stp_Step001',
            'stepType': 'signature',
            'isStarted': False,
            'isFinished': False,
            'recipients': [
                {
                    'consentPageId': 'cop_DefaultConsent',
                    'email': 'signer@example.com',
                    'firstName': 'Jean',
                    'lastName': 'Dupont',
                }
            ],
            'maxInvites': 5,
        }
    ],
    'created': 1700000000000,
    'updated': 1700000000000,
    'userId': 'usr_TestUser123',
    'tenantId': 'ten_TestTenant',
}

MOCK_WORKFLOW_DETAIL = {
    'id': 'wfl_Test001',
    'workflowStatus': 'started',
    'name': 'Test Workflow',
    'workflowMode': 'FULL',
    'progress': 50,
    'steps': [
        {
            'id': 'stp_Step001',
            'stepType': 'signature',
            'isStarted': True,
            'isFinished': False,
            'recipients': [
                {
                    'consentPageId': 'cop_DefaultConsent',
                    'email': 'signer@example.com',
                    'firstName': 'Jean',
                    'lastName': 'Dupont',
                }
            ],
            'maxInvites': 5,
            'logs': [
                {'operation': 'start', 'created': 1700000100000},
                {
                    'operation': 'invite',
                    'recipientEmail': 'signer@example.com',
                    'created': 1700000200000,
                },
            ],
        }
    ],
    'currentRecipientEmails': ['signer@example.com'],
    'currentRecipientUsers': [],
    'started': 1700000100000,
    'created': 1700000000000,
    'updated': 1700000200000,
    'userId': 'usr_TestUser123',
    'tenantId': 'ten_TestTenant',
}

MOCK_UPLOAD_RESPONSE = {
    'documents': [
        {
            'id': 'doc_Doc001',
            'workflowId': 'wfl_Test001',
            'workflowName': 'Test Workflow',
            'signatureProfileId': 'sip_DefaultProfile',
            'parts': [
                {
                    'filename': 'convention.pdf',
                    'contentType': 'application/pdf',
                    'size': 12341,
                    'hash': 'abc123hash',
                }
            ],
            'created': 1700000050000,
            'updated': 1700000050000,
        }
    ],
    'parts': [
        {
            'filename': 'convention.pdf',
            'contentType': 'application/pdf',
            'size': 12341,
            'hash': 'abc123hash',
        }
    ],
    'ignoredAttachments': 0,
}

MOCK_START_RESPONSE = {
    'id': 'wfl_Test001',
    'workflowStatus': 'started',
    'name': 'Test Workflow',
    'progress': 0,
    'started': 1700000100000,
    'created': 1700000000000,
    'updated': 1700000100000,
}

MOCK_VERSION_RESPONSE = 'sgs-wm-webapp:1.19.4-RC1'

MOCK_WORKFLOW_LIST = {
    'items': [MOCK_WORKFLOW_RESPONSE],
    'itemsPerPage': 50,
    'pageIndex': 0,
    'totalItems': 1,
}

MOCK_INVITE_RESPONSE = {
    'inviteUrl': 'https://goodflag.test/invite?token=eyJtest123',
}

MOCK_WEBHOOK_EVENT = {
    'id': 'wbe_Event001',
    'tenantId': 'ten_TestTenant',
    'userId': 'usr_TestUser123',
    'webhookId': 'wbh_Webhook001',
    'workflowId': 'wfl_Test001',
    'eventType': 'workflowFinished',
    'created': 1700000500000,
    'updated': 1700000500000,
}
