import secrets
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class RefreshTokenModel(BaseModel):
    token: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    user_id: str
    app_id: str
    expires_at: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
