"""
Service de préparation des données workflow pour le connecteur Goodflag.

Centralise la logique commune à create_workflow et submit_workflow :
parsing des destinataires, construction des steps, validation des métadonnées,
et assemblage du payload prêt à envoyer au client Goodflag.
"""

import logging

from ..exceptions import GoodflagValidationError

logger = logging.getLogger(__name__)

# Nombre max de destinataires indexés (form-encoded W.C.S.)
_MAX_RECIPIENTS = 100


def get_param(payload, key, default=None):
    """Récupère un paramètre depuis un dict JSON ou form-encoded (liste)."""
    val = payload.get(key, default)
    if isinstance(val, list):
        val = val[0] if val else default
    if val == '' and default is not None:
        return default
    return val


def parse_multi_recipients(payload):
    """
    Parse les destinataires au format form-encoded numéroté de W.C.S.

    Supporte :
    - Format indexé : recipients_0_email, recipients_0_firstname, ...
    - Format JSON  : recipients = [{"email": ..., "firstName": ...}, ...]

    Retourne une liste de dicts recipients ou None si aucun trouvé.
    """
    recipients_raw = payload.get('recipients')
    if recipients_raw and isinstance(recipients_raw, list):
        return recipients_raw

    recipients = []
    i = 0
    while i < _MAX_RECIPIENTS:
        email = get_param(payload, f'recipients_{i}_email')
        if not email:
            break
        recipient = {
            'email': email,
            'firstName': get_param(payload, f'recipients_{i}_firstname', ''),
            'lastName': get_param(payload, f'recipients_{i}_lastname', ''),
            'phone': get_param(payload, f'recipients_{i}_phone', ''),
        }
        consent_page = get_param(payload, f'recipients_{i}_consent_page_id')
        if consent_page:
            recipient['consentPageId'] = consent_page
        sig_profile = get_param(payload, f'recipients_{i}_signature_profile_id')
        if sig_profile:
            recipient['signatureProfileId'] = sig_profile
        recipients.append(recipient)
        i += 1

    return recipients if recipients else None


def build_steps(recipients, steps_config=None, default_consent_page_id='', debug_mode=False):
    """
    Construit la structure steps[] pour l'API Goodflag.

    Si steps_config est fourni, il est utilisé tel quel (format natif Goodflag).
    Sinon, on construit une étape de signature unique à partir de la liste de
    recipients.
    """
    if steps_config:
        for step in steps_config:
            for recipient in step.get('recipients', []):
                if not recipient.get('consentPageId') and default_consent_page_id:
                    recipient['consentPageId'] = default_consent_page_id
        return steps_config

    built_recipients = []
    for r in recipients:
        recipient = dict(r)
        if not recipient.get('consentPageId') and default_consent_page_id:
            recipient['consentPageId'] = default_consent_page_id
        if 'consentPageId' in recipient and not recipient['consentPageId']:
            del recipient['consentPageId']

        # Mapping phone (Publik) -> phoneNumber (Goodflag)
        phone = recipient.pop('phone', None)
        if phone:
            recipient['phoneNumber'] = phone

        built_recipients.append(recipient)

    steps = [{
        'stepType': 'signature',
        'recipients': built_recipients,
        'maxInvites': 5,
    }]

    if debug_mode:
        logger.info("[GOODFLAG DEBUG] built steps: %r", steps)

    return steps


def prepare_workflow_data(payload, resource):
    """
    Prépare toutes les données nécessaires à la création d'un workflow.

    Valide les paramètres, résout les destinataires, construit les steps,
    et retourne un dict prêt à être passé à client.create_workflow().

    Args:
        payload: dict combiné de la requête (JSON + form + query)
        resource: instance GoodflagResource (pour les defaults)

    Returns:
        dict avec les clés : name, steps, metadata, external_ref, layout_id,
        workflow_mode, description, et les options optionnelles.

    Raises:
        GoodflagValidationError si les paramètres sont invalides.
    """
    name = get_param(payload, 'name')
    if not name:
        raise GoodflagValidationError("'name' is required")

    steps_config = payload.get('steps')
    recipients = payload.get('recipients')

    # Interdire la fourniture simultanée de steps et recipients
    if steps_config and recipients:
        raise GoodflagValidationError(
            "'steps' and 'recipients' are mutually exclusive. "
            "Provide either 'steps' (native Goodflag format) or 'recipients' "
            "(simplified format), not both."
        )

    if not steps_config and not recipients:
        recipients = parse_multi_recipients(payload)

    if not steps_config and not recipients:
        recipient_email = get_param(payload, 'recipient_email')
        if recipient_email:
            recipients = [{
                'email': recipient_email,
                'firstName': get_param(payload, 'recipient_firstname', ''),
                'lastName': get_param(payload, 'recipient_lastname', ''),
                'phone': get_param(payload, 'recipient_phone', ''),
            }]

    if not steps_config and not recipients:
        raise GoodflagValidationError(
            "'steps' or 'recipients' is required"
        )

    steps = build_steps(
        recipients=recipients or [],
        steps_config=steps_config,
        default_consent_page_id=resource.default_consent_page_id,
        debug_mode=resource.debug_mode,
    )

    metadata = payload.get('metadata', {})
    external_ref = get_param(payload, 'external_ref', '')
    layout_id = get_param(payload, 'layout_id') or resource.default_layout_id
    workflow_mode = get_param(payload, 'workflow_mode', 'FULL')

    if not resource.user_id:
        raise GoodflagValidationError(
            "Configuration error: 'user_id' is missing in the connector settings."
        )

    return {
        'name': name,
        'steps': steps,
        'metadata': metadata,
        'external_ref': external_ref,
        'layout_id': layout_id,
        'workflow_mode': workflow_mode,
        'description': payload.get('description', ''),
        'notified_events': payload.get('notified_events'),
        'watchers': payload.get('watchers'),
        'template_id': payload.get('template_id'),
        'allow_consolidation': payload.get('allow_consolidation'),
        'allowed_comanager_users': payload.get('allowed_comanager_users'),
        'comanager_notified_events': payload.get('comanager_notified_events'),
    }
