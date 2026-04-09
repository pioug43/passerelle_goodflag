"""
Service de gestion des fichiers pour le connecteur Goodflag.

Regroupe : validation SSRF des URLs, détection de type MIME par magic bytes,
validation du contenu des fichiers, et extraction du fichier depuis le payload.
"""

import base64
import io
import ipaddress
import json
import logging
import zipfile
from urllib.parse import unquote, urlparse

from ..exceptions import GoodflagError, GoodflagValidationError

logger = logging.getLogger(__name__)

# Taille max d'un fichier encodé en base64 (~50 Mo décodé)
MAX_B64_LEN = int(50 * 1024 * 1024 * 4 / 3) + 1024


def sniff_content_type(content, declared_type):
    """
    Détecte le type MIME réel d'un fichier par ses magic bytes.

    WCS renvoie souvent Content-Type: text/html ou application/octet-stream
    même pour des PDFs valides. On se base sur le contenu réel.
    """
    if content[:4] == b'%PDF':
        return 'application/pdf'
    if content[:4] == b'PK\x03\x04':
        return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    if content[:3] in (b'\xff\xd8\xff',):
        return 'image/jpeg'
    if content[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    return declared_type


def validate_file_url(url):
    """
    Valide qu'une URL de fichier est sûre (protection SSRF).

    Seul HTTPS est autorisé. Les adresses IP privées, loopback, link-local
    et les hostnames locaux sont rejetés.

    Lève GoodflagValidationError si l'URL est suspecte.
    """
    if not url:
        raise GoodflagValidationError("file_url is required")
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise GoodflagValidationError(
            f"file_url scheme '{parsed.scheme}' not allowed (https only)"
        )
    hostname = parsed.hostname or ''
    # Rejeter les IP littérales privées / réservées
    try:
        addr = ipaddress.ip_address(hostname)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            raise GoodflagValidationError(
                f"file_url points to a non-routable address: {hostname}"
            )
    except ValueError:
        pass
    # Rejeter les hostnames clairement locaux
    local_patterns = ('localhost', '127.', '0.0.0.0', '::1', 'metadata.google',
                      '169.254.', 'metadata.internal')
    for pat in local_patterns:
        if hostname.lower().startswith(pat) or hostname.lower() == pat.rstrip('.'):
            raise GoodflagValidationError(
                f"file_url points to a local/internal address: {hostname}"
            )


def validate_file_content(content, content_type):
    """
    Valide le contenu d'un fichier avant upload vers Goodflag.

    Vérifie :
    - PDF : signature magique, absence de chiffrement, non vide
    - DOCX : signature ZIP, fichier word/document.xml présent
    - Taille non nulle

    Lève GoodflagValidationError si le fichier est invalide.
    """
    if not content:
        raise GoodflagValidationError("Le fichier est vide")

    is_pdf_by_content = content.startswith(b'%PDF')
    is_pdf_by_type = 'pdf' in content_type.lower()

    if is_pdf_by_content or is_pdf_by_type:
        if is_pdf_by_type and not is_pdf_by_content:
            raise GoodflagValidationError(
                "Le fichier n'est pas un PDF valide (signature %PDF manquante). "
                "Vérifiez que l'URL du document est accessible et retourne bien un PDF."
            )
        probe = content[:2048] + content[-512:]
        if b'/Encrypt' in probe:
            raise GoodflagValidationError(
                "Le PDF est protégé par chiffrement. "
                "Goodflag ne peut pas signer un PDF chiffré. "
                "Déchiffrez le document avant de l'uploader."
            )

    elif 'wordprocessingml' in content_type or 'docx' in content_type.lower():
        if not content.startswith(b'PK\x03\x04'):
            raise GoodflagValidationError(
                "Le fichier DOCX n'est pas valide (signature ZIP manquante)"
            )
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = zf.namelist()
                if 'word/document.xml' not in names:
                    raise GoodflagValidationError(
                        "Le fichier DOCX est corrompu (word/document.xml manquant)"
                    )
        except zipfile.BadZipFile:
            raise GoodflagValidationError(
                "Le fichier DOCX est corrompu (archive ZIP invalide)"
            )


def parse_file_from_payload(payload, request, passerelle_session=None, get_param=None):
    """
    Extrait le contenu d'un fichier depuis le payload ou la requête.

    Priorité :
      1. ``file`` (dict JSON)
      2. ``request.FILES['file']`` — upload multipart Django
      3. ``file_base64`` — chaîne base64 directe
      4. ``file_url`` — URL téléchargée via la session Passerelle signée (HTTPS)
      5. ``fields`` — objet de formulaire WCS complet

    Retourne (file_content: bytes, filename: str, content_type: str).
    Lève GoodflagValidationError si aucune source n'est trouvable.
    """
    if get_param is None:
        def get_param(key, default=None):
            val = payload.get(key, default)
            if isinstance(val, list):
                val = val[0] if val else default
            if val == '' and default is not None:
                return default
            return val

    file_obj = payload.get('file')
    if isinstance(file_obj, str) and file_obj.startswith('{'):
        try:
            file_obj = json.loads(file_obj)
        except (ValueError, TypeError):
            pass

    filename = get_param('filename')
    content_type = get_param('content_type', 'application/pdf')
    file_content = None
    file_url = None

    if isinstance(file_obj, dict):
        file_b64 = file_obj.get('content')
        if not file_b64:
            raise GoodflagValidationError("'content' is missing in 'file' object")
        if len(file_b64) > MAX_B64_LEN:
            raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
        file_content = base64.b64decode(file_b64)
        filename = filename or file_obj.get('filename')
        content_type = file_obj.get('content_type') or content_type
    elif request.FILES.get('file'):
        f = request.FILES['file']
        file_content = f.read()
        filename = filename or f.name
    elif get_param('file_base64'):
        file_b64 = get_param('file_base64')
        if len(file_b64) > MAX_B64_LEN:
            raise GoodflagValidationError("File content exceeds maximum allowed size (50 MB)")
        file_content = base64.b64decode(file_b64)
    elif get_param('file_url'):
        file_url = get_param('file_url')
        validate_file_url(file_url)
        if passerelle_session is None:
            raise GoodflagValidationError(
                "file_url requires the Passerelle signed session (self.requests) "
                "to fetch files securely. Direct HTTP fetch is not allowed."
            )
        resp = passerelle_session.get(file_url)
        if resp.status_code != 200:
            raise GoodflagError(
                f"Failed to fetch file from URL: HTTP {resp.status_code}"
            )
        file_content = resp.content
        content_type = sniff_content_type(file_content, content_type)
    elif isinstance(payload.get('fields'), dict):
        for field_val in payload['fields'].values():
            if isinstance(field_val, dict) and 'content' in field_val:
                file_content = base64.b64decode(field_val['content'])
                filename = filename or field_val.get('filename')
                content_type = field_val.get('content_type') or content_type
                break

    if not file_content:
        raise GoodflagValidationError(
            "'file' object, 'file_base64', 'file_url' or valid 'fields' is required"
        )

    validate_file_content(file_content, content_type)

    if not filename and file_url:
        path = urlparse(file_url).path
        filename = unquote(path.rstrip('/').rsplit('/', 1)[-1]) or ''
    filename = filename or 'document.pdf'

    return file_content, filename, content_type
