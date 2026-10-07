from datetime import datetime, timezone

from pydantic import BaseModel, Field


class RoleCreate(BaseModel):
    name: str
    description: str = ""
    permissions: list[str] = []

class RoleResponse(BaseModel):
    id: str
    name: str
    description: str
    permissions: list[str]
    created_at: str

class RoleModel(BaseModel):
    app_id: str
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
