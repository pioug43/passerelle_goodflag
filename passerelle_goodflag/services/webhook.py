"""
Service de traitement des webhooks Goodflag.

Regroupe :
- Validation du token d'URL
- Détection anti-rejeu (idempotence par event_id)
- Re-validation via l'API webhookEvents
- Enregistrement de l'événement
- Notification WCS via callback
"""

import hmac
import json
import logging

from django.http import JsonResponse
from django.utils import timezone

from ..exceptions import GoodflagError

logger = logging.getLogger(__name__)

# Types d'événements déclenchant une notification WCS
NOTIFY_EVENT_TYPES = frozenset({
    'workflowFinished', 'workflowStopped', 'workflowStarted',
    'recipientFinished', 'recipientRefused',
})


def validate_webhook_token(request, webhook_secret):
    """
    Valide le token webhook passé dans l'URL.

    Retourne une JsonResponse d'erreur si invalide, ou None si OK.
    """
    if not webhook_secret:
        return None
    provided_token = request.GET.get('token', '')
    if not hmac.compare_digest(provided_token, webhook_secret):
        logger.warning(
            "Webhook token validation failed: got=%s",
            provided_token[:4] + '...' if provided_token else '(empty)',
        )
        return JsonResponse({'error': 'Invalid token'}, status=403)
    return None


def check_replay(resource, event_id):
    """
    Vérifie si un événement webhook a déjà été traité (anti-rejeu).

    Retourne True si l'événement est un doublon.
    """
    from ..models import GoodflagWebhookEvent

    return GoodflagWebhookEvent.objects.filter(
        resource=resource,
        event_id=event_id,
    ).exists()


def verify_and_fetch_status(client, event_id, workflow_id):
    """
    Re-valide l'événement via l'API Goodflag et récupère le statut courant.

    Retourne (raw_status, normalized_status, error_response_or_None).
    ``error_response`` est une JsonResponse si la vérification échoue.
    """
    try:
        verified_event = client.get_webhook_event(event_id)
        if verified_event.get('workflowId') != workflow_id:
            logger.warning(
                "Webhook event workflowId mismatch: received=%s, verified=%s",
                workflow_id, verified_event.get('workflowId'),
            )
            return '', '', JsonResponse({'error': 'Event verification failed'}, status=403)

        wf_data = client.get_workflow(workflow_id)
        return wf_data.get('status', ''), wf_data.get('normalized_status', ''), None
    except GoodflagError as exc:
        logger.warning("Failed to re-validate webhook via API: %s", exc)
        return 'unverified', 'error', None


def record_event(resource, event_id, event_type, workflow_id,
                 webhook_id, step_id, raw_status, normalized_status,
                 payload, created):
    """
    Enregistre un événement webhook et met à jour la trace workflow.
    """
    from ..models import GoodflagWebhookEvent, GoodflagWorkflowTrace

    GoodflagWebhookEvent.objects.create(
        resource=resource,
        event_id=event_id,
        event_type=event_type,
        goodflag_workflow_id=workflow_id,
        webhook_id=webhook_id,
        step_id=step_id,
        raw_status=raw_status,
        normalized_status=normalized_status,
        payload_json=json.dumps(payload),
        timestamp_goodflag=str(created),
    )

    if workflow_id and normalized_status:
        GoodflagWorkflowTrace.objects.filter(
            resource=resource,
            goodflag_workflow_id=workflow_id,
        ).update(
            status=normalized_status,
            updated_at=timezone.now(),
        )


def notify_wcs(requests_session, callback_url, workflow_id, event_type,
               normalized_status, event_id=''):
    """
    Notifie WCS d'un changement de statut via le publik_callback_url.

    Utilise la session HTTP Passerelle (signature d'URL) pour que WCS
    accepte l'appel.
    """
    if not callback_url:
        return

    payload = {
        'event_type': event_type,
        'workflow_id': workflow_id,
        'status': normalized_status,
        'event_id': event_id,
    }

    try:
        cb_response = requests_session.post(
            callback_url,
            json=payload,
            timeout=10,
        )
        if cb_response.status_code >= 400:
            logger.warning(
                "WCS callback failed: HTTP %s for workflow %s (url=%s)",
                cb_response.status_code, workflow_id, callback_url,
            )
        else:
            logger.info(
                "WCS callback OK: workflow=%s, status=%s, HTTP %s",
                workflow_id, normalized_status, cb_response.status_code,
            )
    except Exception as exc:
        logger.warning(
            "WCS callback exception for workflow %s: %s (url=%s)",
            workflow_id, exc, callback_url,
        )
