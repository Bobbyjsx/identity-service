from datetime import datetime, timezone

from pydantic import BaseModel, EmailStr, Field


class UserModel(BaseModel):
    app_id: str
    email: EmailStr
    hashed_password: str
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
