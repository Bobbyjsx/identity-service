import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import StatusEnum


class ApplicationModel(BaseModel):
    name: str
    description: str | None = None
    client_id: str = Field(default_factory=lambda: f"app_{uuid.uuid4().hex}")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE

    model_config = ConfigDict(use_enum_values=True)

class ApplicationCredentialModel(BaseModel):
    app_id: str
    hashed_secret: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE

    model_config = ConfigDict(use_enum_values=True)
