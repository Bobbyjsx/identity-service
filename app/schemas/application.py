import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.core.security import validate_redirect_uri
from app.schemas.enums import StatusEnum

COLOR_PATTERN = r"^#[0-9a-fA-F]{6}$"

KNOWN_OAUTH_SCOPES = {"openid", "profile", "email", "offline_access"}
KNOWN_GRANT_TYPES = {"authorization_code", "client_credentials"}


class ApplicationCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str | None, Field(max_length=1000)] = None


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


class ApplicationBranding(BaseModel):
    logo_url: HttpUrl | None = None
    primary_color: Annotated[str | None, Field(pattern=COLOR_PATTERN)] = None
    secondary_color: Annotated[str | None, Field(pattern=COLOR_PATTERN)] = None


class ApplicationAuthenticationConfig(BaseModel):
    allow_signup: bool = True
    allow_password_login: bool = True
    require_email_verification: bool = False


class ApplicationOAuthConfig(BaseModel):
    redirect_uris: list[str] = Field(default_factory=list, max_length=20)
    allowed_scopes: list[Literal["openid", "profile", "email", "offline_access"]] = Field(
        default_factory=lambda: ["openid", "profile", "email"]
    )
    allowed_grants: list[Literal["authorization_code", "client_credentials"]] = Field(
        default_factory=lambda: ["authorization_code", "client_credentials"]
    )

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, uris: list[str]) -> list[str]:
        for uri in uris:
            validate_redirect_uri(uri)
        return uris


class ApplicationConfigUpdate(BaseModel):
    """Admin-only partial update for application hosted-login configuration."""

    name: Annotated[str | None, Field(min_length=1, max_length=120)] = None
    description: Annotated[str | None, Field(max_length=1000)] = None
    branding: ApplicationBranding | None = None
    authentication: ApplicationAuthenticationConfig | None = None
    oauth: ApplicationOAuthConfig | None = None


class PublicApplicationConfig(BaseModel):
    """Safe public application configuration exposed to the hosted Identity UI."""

    name: str
    description: str | None = None
    logo_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    allow_signup: bool
    allow_password_login: bool
    require_email_verification: bool
    allowed_scopes: list[str]


class ApplicationModel(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str | None, Field(max_length=1000)] = None
    client_id: str = Field(default_factory=lambda: f"app_{uuid.uuid4().hex}")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE
    branding: ApplicationBranding = Field(default_factory=ApplicationBranding)
    authentication: ApplicationAuthenticationConfig = Field(default_factory=ApplicationAuthenticationConfig)
    oauth: ApplicationOAuthConfig = Field(default_factory=ApplicationOAuthConfig)

    model_config = ConfigDict(use_enum_values=True)


class ApplicationCredentialModel(BaseModel):
    app_id: str
    hashed_secret: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE

    model_config = ConfigDict(use_enum_values=True)
