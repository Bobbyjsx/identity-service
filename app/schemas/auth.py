
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None

class OAuth2ClientCredentialsRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str
