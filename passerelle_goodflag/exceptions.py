class GoodflagError(Exception):
    def __init__(self, message, status_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class GoodflagAuthError(GoodflagError):
    pass


class GoodflagValidationError(GoodflagError):
    pass
