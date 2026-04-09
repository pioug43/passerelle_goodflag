"""
Service de téléchargement des documents signés et certificats de preuve.

Fournit des helpers pour construire les réponses HTTP de téléchargement
depuis les résultats du client Goodflag.
"""

import logging

from django.http import HttpResponse, StreamingHttpResponse

logger = logging.getLogger(__name__)


def build_download_response(result):
    """
    Construit une réponse HTTP de téléchargement depuis le résultat du client.

    Args:
        result: dict retourné par client.download_documents() ou
                client.download_evidence_certificate()

    Returns:
        StreamingHttpResponse ou HttpResponse avec le contenu binaire.
    """
    if 'response' in result:
        streaming_response = StreamingHttpResponse(
            result['response'].iter_content(chunk_size=8192),
            content_type=result['content_type'],
        )
        streaming_response['Content-Disposition'] = (
            f'attachment; filename="{result["filename"]}"'
        )
        return streaming_response

    response = HttpResponse(
        result.get('content', b''),
        content_type=result['content_type'],
    )
    response['Content-Disposition'] = (
        f'attachment; filename="{result["filename"]}"'
    )
    return response
