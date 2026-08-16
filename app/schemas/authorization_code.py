import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AuthorizationCodeStatus(str, Enum):
    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"


def generate_authorization_code() -> str:
    """
    Generates a high-entropy authorization code.

    The raw code is returned to the browser exactly once and is never
    persisted; only its SHA-256 hash is stored.
    """
    return f"code_{secrets.token_urlsafe(48)}"


class AuthorizationCodeModel(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    code_hash: str
    session_id: str
    application_id: str
    client_id: str
    user_id: str
    redirect_uri: str
    scopes: list[str] = Field(default_factory=list)
    code_challenge: str
    code_challenge_method: str = "S256"
    nonce: str | None = None
    status: AuthorizationCodeStatus = AuthorizationCodeStatus.ACTIVE
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = Field(
        default_factory=lambda: (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat()
    )
    used_at: str | None = None

    model_config = ConfigDict(use_enum_values=True)
