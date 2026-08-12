from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ApplicationCreate(BaseModel):
    name: str
    description: str | None = None

class ApplicationResponse(BaseModel):
    id: str
    name: str
    description: str | None
    client_id: str
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class ApplicationCredentials(BaseModel):
    client_id: str
    client_secret: str
