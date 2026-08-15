import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class OAuthTransactionStatus(str, Enum):
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


# Stored-state transitions only. `expired` is derived at read time from expires_at
# and is never a legal source or target of a written transition.
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    OAuthTransactionStatus.PENDING.value: frozenset(
        {
            OAuthTransactionStatus.AUTHENTICATED.value,
            OAuthTransactionStatus.COMPLETED.value,
            OAuthTransactionStatus.CANCELLED.value,
        }
    ),
    OAuthTransactionStatus.AUTHENTICATED.value: frozenset(
        {
            OAuthTransactionStatus.COMPLETED.value,
            OAuthTransactionStatus.CANCELLED.value,
        }
    ),
    OAuthTransactionStatus.COMPLETED.value: frozenset(),
    OAuthTransactionStatus.CANCELLED.value: frozenset(),
    OAuthTransactionStatus.EXPIRED.value: frozenset(),
}


def generate_transaction_id() -> str:
    """
    Generates a high-entropy opaque transaction identifier.

    The transaction ID is a bearer capability and must not be guessable:
    secrets.token_urlsafe(32) provides 256 bits of entropy.
    """
    return f"tx_{secrets.token_urlsafe(32)}"


class OAuthTransactionModel(BaseModel):
    id: str = Field(default_factory=generate_transaction_id)
    application_id: str
    client_id: str
    redirect_uri: str
    response_type: str = "code"
    scopes: list[str] = Field(default_factory=list)
    state: str | None = None
    code_challenge: str
    code_challenge_method: str = "S256"
    nonce: str | None = None
    status: OAuthTransactionStatus = OAuthTransactionStatus.PENDING
    user_id: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = Field(default_factory=lambda: (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat())
    completed_at: str | None = None

    model_config = ConfigDict(use_enum_values=True)


class OAuthTransactionResponse(BaseModel):
    """Safe representation of a transaction for the hosted Identity frontend."""

    transaction_id: str
    status: str
    application: dict
    scopes: list[str]
