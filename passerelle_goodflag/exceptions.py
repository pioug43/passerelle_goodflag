"""Exceptions métier du connecteur Goodflag."""


class GoodflagError(Exception):
    """Erreur générique Goodflag."""

    def __init__(self, message, status_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class GoodflagAuthError(GoodflagError):
    """Erreur d'authentification (token invalide, expiré, etc.)."""

    pass


class GoodflagNotFoundError(GoodflagError):
    """Ressource non trouvée côté Goodflag."""

    pass


class GoodflagValidationError(GoodflagError):
    """Erreur de validation des paramètres."""

    pass


class GoodflagTimeoutError(GoodflagError):
    """Timeout lors d'un appel API Goodflag."""

    pass


class GoodflagUploadError(GoodflagError):
    """Erreur lors de l'upload d'un document."""

    pass


class GoodflagRateLimitError(GoodflagError):
    """Rate limit atteint (HTTP 429). Utiliser retry_after pour patienter."""

    def __init__(self, message, retry_after=None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after  # secondes à attendre avant de réessayer
