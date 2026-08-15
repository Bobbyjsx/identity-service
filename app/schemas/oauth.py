import re
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

PKCE_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


class AuthorizationRequest(BaseModel):
    """Standard OAuth 2.0 authorization request parameters."""

    client_id: str
    redirect_uri: Annotated[str, Field(max_length=2048)]
    response_type: str = "code"
    scope: str | None = None
    state: Annotated[str | None, Field(max_length=256)] = None
    code_challenge: Annotated[str, Field(min_length=43, max_length=128)]
    code_challenge_method: str = "S256"
    nonce: Annotated[str | None, Field(max_length=256)] = None

    @field_validator("code_challenge")
    @classmethod
    def validate_code_challenge(cls, value: str) -> str:
        if not PKCE_CHALLENGE_PATTERN.match(value):
            raise ValueError("code_challenge must be a valid base64url-encoded value (43-128 chars)")
        return value

    @field_validator("code_challenge_method")
    @classmethod
    def validate_code_challenge_method(cls, value: str) -> str:
        if value != "S256":
            raise ValueError("only the S256 code challenge method is supported")
        return value


class LoginRequest(BaseModel):
    email: Annotated[str, Field(max_length=254)]
    password: Annotated[str, Field(max_length=1024)]


class SignupRequest(BaseModel):
    email: Annotated[str, Field(max_length=254)]
    password: Annotated[str, Field(min_length=8, max_length=1024)]
    username: Annotated[str | None, Field(max_length=64)] = None
    first_name: Annotated[str | None, Field(max_length=64)] = None
    last_name: Annotated[str | None, Field(max_length=64)] = None


class ForgotPasswordRequest(BaseModel):
    email: Annotated[str, Field(max_length=254)]


class ResetPasswordRequest(BaseModel):
    reset_token: Annotated[str, Field(min_length=16, max_length=512)]
    new_password: Annotated[str, Field(min_length=8, max_length=1024)]


class VerifyEmailRequest(BaseModel):
    verification_token: Annotated[str, Field(min_length=16, max_length=512)]


class OAuthRedirectResponse(BaseModel):
    """Returned to the hosted UI after successful authentication; the frontend
    performs the browser navigation to the registered redirect URI."""

    redirect_url: str


class OAuthFlowResponse(BaseModel):
    """Generic success response for flows that must not leak account state."""

    detail: str = "ok"


class TokenExchangeRequest(BaseModel):
    """Authorization-code token exchange parameters (form-encoded)."""

    grant_type: str
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str
    client_secret: str | None = None
