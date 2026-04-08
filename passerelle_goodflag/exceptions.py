"""Exceptions métier du connecteur Goodflag."""


class GoodflagError(Exception):
    """Erreur générique Goodflag."""

    def __init__(self, message, status_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class GoodflagAuthError(GoodflagError):
    """Token invalide, expiré, ou droits insuffisants."""


class GoodflagNotFoundError(GoodflagError):
    """Ressource non trouvée côté Goodflag."""


class GoodflagValidationError(GoodflagError):
    """Paramètres d'entrée invalides."""


class GoodflagTimeoutError(GoodflagError):
    """Timeout lors d'un appel API."""


class GoodflagUploadError(GoodflagError):
    """Échec d'upload de document."""


class GoodflagRateLimitError(GoodflagError):
    """Rate limit atteint (HTTP 429)."""

    def __init__(self, message, retry_after=None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after
