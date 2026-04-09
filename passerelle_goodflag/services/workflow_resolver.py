"""
Service de résolution workflow_id / external_ref.

Permet de retrouver un workflow Goodflag à partir d'une référence externe
Publik (display_id, uuid) sans couplage direct avec le modèle Django.
"""

import logging

logger = logging.getLogger(__name__)


def resolve_workflow_id(resource, payload, get_param):
    """
    Résout le workflow_id depuis le payload.

    Cherche d'abord workflow_id directement, puis utilise external_ref
    comme fallback pour retrouver le workflow depuis la trace locale.
    Cela permet de récupérer le workflow_id même si la variable WCS
    goodflag_create_data_workflow_id n'a pas été correctement propagée.

    Args:
        resource: instance GoodflagResource (pour filtrer les traces).
        payload: dict fusionné des paramètres de la requête.
        get_param: callable(payload, key, default=None).

    Retourne le workflow_id (str) ou None.
    """
    # Import tardif pour éviter les imports circulaires
    from ..models import GoodflagWorkflowTrace

    workflow_id = get_param(payload, 'workflow_id')
    if not workflow_id:
        external_ref = (
            get_param(payload, 'external_ref')
            or get_param(payload, 'display_id')   # ex: "12-1"
            or get_param(payload, 'uuid')          # ex: "a02ca561-..."
            # Note: 'id' retiré — trop générique, risque de collision
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
