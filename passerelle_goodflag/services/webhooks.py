"""
Service de traitement et persistance des webhooks Goodflag.

Regroupe la logique de validation, re-validation API, idempotence,
persistance et mise à jour des traces workflow.
"""

import json
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from ..exceptions import GoodflagError

logger = logging.getLogger(__name__)


def process_webhook(resource, payload, client):
    """
    Traite un événement webhook Goodflag.

    Étapes :
    1. Extraire les champs du payload (compatibilité variantes de clés)
    2. Vérifier l'idempotence (anti-rejeu atomique)
    3. Re-valider via l'API Goodflag
    4. Persister l'événement
    5. Mettre à jour la trace workflow

    Args:
        resource: instance GoodflagResource
        payload: dict du corps JSON du webhook
        client: instance GoodflagClient (ou None si pas de secret et revalidation requise)

    Returns:
        dict avec 'status', 'status_code', et optionnellement d'autres infos.
    """
    from ..models import GoodflagWebhookEvent, GoodflagWorkflowTrace

    # Compatibilité variantes de payload Goodflag
    event_id = payload.get('id', '')
    event_type = payload.get('eventType') or payload.get('event', '')
    workflow_id = payload.get('workflowId') or payload.get('workflow_id', '')

    if not event_id:
        logger.warning("Webhook received without event_id, rejecting")
        return {'status': 'error', 'error': 'Missing event id', 'status_code': 400}

    webhook_id = payload.get('webhookId') or payload.get('webhook_id', '')
    step_id = payload.get('stepId') or payload.get('step_id', '')
    created = payload.get('created', '')

    logger.info(
        "Webhook received: event_id=%s, event_type=%s, workflow_id=%s",
        event_id, event_type, workflow_id,
    )

    # Idempotence atomique : get_or_create dans une transaction
    # pour éviter les doublons concurrents
    with transaction.atomic():
        _event, created_new = GoodflagWebhookEvent.objects.get_or_create(
            resource=resource,
            event_id=event_id,
            defaults={
                'event_type': event_type,
                'goodflag_workflow_id': workflow_id,
                'webhook_id': webhook_id,
                'step_id': step_id,
                'payload_json': json.dumps(payload),
                'timestamp_goodflag': str(created),
            },
        )

    if not created_new:
        logger.info(
            "Webhook event already processed, skipping: event_id=%s",
            event_id,
        )
        return {'status': 'already_processed', 'status_code': 200}

    # Re-validation via l'API Goodflag
    raw_status = ''
    normalized_status = ''
    revalidation_ok = False

    if event_id and workflow_id:
        try:
            verified_event = client.get_webhook_event(event_id)
            if verified_event.get('workflowId') != workflow_id:
                logger.warning(
                    "Webhook event workflowId mismatch: received=%s, verified=%s",
                    workflow_id, verified_event.get('workflowId'),
                )
                # Supprimer l'événement créé — la vérification a échoué
                GoodflagWebhookEvent.objects.filter(
                    resource=resource, event_id=event_id,
                ).delete()
                return {
                    'status': 'error',
                    'error': 'Event verification failed',
                    'status_code': 403,
                }

            # Récupérer le statut actuel du workflow
            wf_data = client.get_workflow(workflow_id)
            raw_status = wf_data.get('status', '')
            normalized_status = wf_data.get('normalized_status', '')
            revalidation_ok = True
        except GoodflagError as exc:
            logger.warning("Failed to re-validate webhook via API: %s", exc)
            # Si pas de webhook_secret, la revalidation est obligatoire :
            # on supprime l'événement et on refuse
            if not resource.webhook_secret:
                GoodflagWebhookEvent.objects.filter(
                    resource=resource, event_id=event_id,
                ).delete()
                return {
                    'status': 'error',
                    'error': 'Revalidation failed and no webhook_secret configured',
                    'status_code': 403,
                }
            # Avec un webhook_secret, on accepte malgré l'échec de revalidation
            raw_status = 'unverified'
            normalized_status = 'error'

    # Mettre à jour l'événement avec les statuts
    GoodflagWebhookEvent.objects.filter(
        resource=resource, event_id=event_id,
    ).update(
        raw_status=raw_status,
        normalized_status=normalized_status,
    )

    # Mise à jour de la trace workflow
    if workflow_id and normalized_status:
        GoodflagWorkflowTrace.objects.filter(
            resource=resource,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=normalized_status,
            updated_at=timezone.now(),
        )

    return {'status': 'ok', 'status_code': 200}
