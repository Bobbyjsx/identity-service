from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


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
