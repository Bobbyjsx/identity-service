import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class PasswordResetTokenStatus(str, Enum):
    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"


def generate_reset_token() -> str:
    """Generates a high-entropy password reset token (256 bits of entropy)."""
    return f"pr_{secrets.token_urlsafe(32)}"


class PasswordResetTokenModel(BaseModel):
    id: str = Field(default_factory=lambda: f"prt_{secrets.token_urlsafe(16)}")
    token_hash: str
    app_id: str
    user_id: str
    status: PasswordResetTokenStatus = PasswordResetTokenStatus.ACTIVE
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = Field(
        default_factory=lambda: (
            datetime.now(timezone.utc) + timedelta(minutes=30)
        ).isoformat()
    )
    used_at: str | None = None

    model_config = ConfigDict(use_enum_values=True)
