"""
Service de construction de réponses HTTP de téléchargement.

Factorise le pattern commun streaming / non-streaming utilisé par
download-signed-documents et download-evidence.
"""

from django.http import HttpResponse, StreamingHttpResponse


def build_download_response(result):
    """
    Construit une réponse HTTP (streaming ou non) à partir du résultat
    retourné par ``client.download_documents()`` ou
    ``client.download_evidence_certificate()``.

    Le dict ``result`` doit contenir :
    - ``content_type`` : type MIME de la réponse
    - ``filename`` : nom du fichier pour Content-Disposition
    - ``response`` (optionnel) : objet requests.Response pour le streaming
    - ``content`` (optionnel) : bytes du contenu complet
    """
    if 'response' in result:
        response = StreamingHttpResponse(
            result['response'].iter_content(chunk_size=8192),
            content_type=result['content_type'],
        )
    else:
        response = HttpResponse(
            result.get('content', b''),
            content_type=result['content_type'],
        )
    response['Content-Disposition'] = (
        f'attachment; filename="{result["filename"]}"'
    )
    return response
