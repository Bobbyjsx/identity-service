from datetime import datetime, timezone

from pydantic import BaseModel, Field


class PermissionCreate(BaseModel):
    name: str
    description: str = ""

class PermissionResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: str

class PermissionModel(BaseModel):
    app_id: str
    name: str
    description: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
