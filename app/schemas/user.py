from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None

class UserResponse(BaseModel):
    id: str
    app_id: str
    email: EmailStr
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    created_at: datetime
    roles: list[str] = []

    model_config = ConfigDict(from_attributes=True)

class UserModel(BaseModel):
    app_id: str
    email: EmailStr
    hashed_password: str
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
