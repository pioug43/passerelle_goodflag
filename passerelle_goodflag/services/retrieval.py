"""
Service de résolution et recherche de workflows Goodflag.

Résolution workflow_id depuis payload (direct ou via external_ref),
et recherche par référence externe avec fallback API distante.
"""

import logging

from ..exceptions import GoodflagValidationError

logger = logging.getLogger(__name__)


def resolve_workflow_id(resource, payload, get_param=None):
    """
    Résout le workflow_id depuis le payload.

    Cherche d'abord workflow_id directement, puis utilise external_ref
    comme fallback pour retrouver le workflow depuis la trace locale.
    """
    from ..models import GoodflagWorkflowTrace

    if get_param is None:
        def get_param(key, default=None):
            val = payload.get(key, default)
            if isinstance(val, list):
                val = val[0] if val else default
            if val == '' and default is not None:
                return default
            return val

    workflow_id = get_param('workflow_id')
    if not workflow_id:
        external_ref = (
            get_param('external_ref')
            or get_param('display_id')
            or get_param('uuid')
        )
        if external_ref:
            trace = GoodflagWorkflowTrace.objects.filter(
                resource=resource,
                external_ref=external_ref,
            ).order_by('-created_at').first()
            if trace:
                workflow_id = trace.goodflag_workflow_id
                logger.info(
                    "Resolved workflow_id=%s from external_ref=%s",
                    workflow_id, external_ref,
                )
    return workflow_id


def retrieve_by_external_ref(resource, external_ref, client=None):
    """
    Retrouve les workflows associés à une référence externe Publik.

    Recherche dans la trace locale sans filtrer par user_id.
    Si aucun résultat local et qu'un client est fourni, tente une
    recherche distante via l'API Goodflag.

    Args:
        resource: instance GoodflagResource
        external_ref: référence externe Publik
        client: instance GoodflagClient optionnelle pour fallback distant

    Returns:
        dict avec 'count' et 'results'.
    """
    from ..models import GoodflagWorkflowTrace

    if not external_ref:
        raise GoodflagValidationError("'external_ref' is required")

    traces = GoodflagWorkflowTrace.objects.filter(
        resource=resource,
        external_ref=external_ref,
    ).order_by('-created_at')

    results = []
    for trace in traces:
        results.append({
            'workflow_id': trace.goodflag_workflow_id,
            'workflow_name': trace.workflow_name,
            'external_ref': trace.external_ref,
            'status': trace.status,
            'created_at': trace.created_at.isoformat(),
            'updated_at': trace.updated_at.isoformat(),
        })

    # Fallback : recherche distante via l'API Goodflag si aucun résultat local
    if not results and client:
        try:
            search_result = client.search_workflows(text=external_ref)
            for wf in search_result.get('items', []):
                # Vérifier que la référence externe correspond (dans data1..data16)
                match = any(
                    wf.get(f'data{i}') == external_ref
                    for i in range(1, 17)
                )
                if match or external_ref in (wf.get('name') or ''):
                    results.append({
                        'workflow_id': wf.get('id', ''),
                        'workflow_name': wf.get('name', ''),
                        'external_ref': external_ref,
                        'status': wf.get('workflowStatus', ''),
                        'created_at': '',
                        'updated_at': '',
                        'source': 'remote',
                    })
        except Exception as exc:
            logger.warning(
                "Remote search for external_ref=%s failed: %s",
                external_ref, exc,
            )

    return {
        'count': len(results),
        'results': results,
    }
