class OAuthError(Exception):
    """
    Structured OAuth-flavored error rendered as:

        {"error": "...", "error_description": "..."}

    Used by the OAuth / OIDC endpoints so the hosted Identity frontend and
    consuming applications receive machine-readable errors instead of 500s.
    """

    def __init__(self, error: str, error_description: str, status_code: int = 400):
        super().__init__(error_description)
        self.error = error
        self.error_description = error_description
        self.status_code = status_code
