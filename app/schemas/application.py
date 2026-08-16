import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.core.security import validate_redirect_uri
from app.schemas.enums import StatusEnum

COLOR_PATTERN = r"^#[0-9a-fA-F]{6}$"
UNSAFE_TEXT = re.compile(r"[<>]|javascript:", re.IGNORECASE)

ClientType = Literal["public", "confidential"]
KNOWN_OAUTH_SCOPES = {"openid", "profile", "email"}
KNOWN_GRANT_TYPES = {"authorization_code", "client_credentials"}
DEFAULT_ALLOWED_SCOPES = ["openid", "profile", "email"]
DEFAULT_ALLOWED_GRANTS = ["authorization_code"]
DEFAULT_CLIENT_TYPE: ClientType = "public"


def reject_unsafe_text(value: str | None) -> str | None:
    """Rejects values that could inject markup into a hosted UI."""
    if value is None:
        return value
    if UNSAFE_TEXT.search(value):
        raise ValueError("contains characters that are not allowed")
    return value


class ApplicationBranding(BaseModel):
    logo_url: HttpUrl | None = None
    logo_with_text: HttpUrl | None = None
    primary_color: Annotated[str | None, Field(pattern=COLOR_PATTERN)] = None
    secondary_color: Annotated[str | None, Field(pattern=COLOR_PATTERN)] = None


class ApplicationAuthenticationConfig(BaseModel):
    allow_signup: bool = True
    allow_password_login: bool = True
    require_email_verification: bool = False


class ApplicationOAuthConfig(BaseModel):
    redirect_uris: list[str] = Field(default_factory=list, max_length=20)
    allowed_scopes: list[Literal["openid", "profile", "email"]] = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_SCOPES)
    )
    allowed_grants: list[Literal["authorization_code", "client_credentials"]] = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_GRANTS)
    )

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, uris: list[str]) -> list[str]:
        for uri in uris:
            validate_redirect_uri(uri)
        return uris


class ApplicationCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str | None, Field(max_length=1000)] = None
    client_type: ClientType = DEFAULT_CLIENT_TYPE
    branding: ApplicationBranding | None = None
    authentication: ApplicationAuthenticationConfig | None = None
    oauth: ApplicationOAuthConfig | None = None

    @field_validator("name", "description")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        return reject_unsafe_text(value)


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


class ApplicationConfigUpdate(BaseModel):
    """Admin-only partial update for application hosted-login configuration."""

    name: Annotated[str | None, Field(min_length=1, max_length=120)] = None
    description: Annotated[str | None, Field(max_length=1000)] = None
    client_type: ClientType | None = None
    branding: ApplicationBranding | None = None
    authentication: ApplicationAuthenticationConfig | None = None
    oauth: ApplicationOAuthConfig | None = None

    @field_validator("name", "description")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        return reject_unsafe_text(value)


class PublicApplicationConfig(BaseModel):
    """Safe public application configuration exposed to the hosted Identity UI."""

    name: str
    description: str | None = None
    logo_url: str | None = None
    logo_with_text: str | None = None
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
    client_type: ClientType = DEFAULT_CLIENT_TYPE
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE
    branding: ApplicationBranding = Field(default_factory=ApplicationBranding)
    authentication: ApplicationAuthenticationConfig = Field(default_factory=ApplicationAuthenticationConfig)
    oauth: ApplicationOAuthConfig = Field(default_factory=ApplicationOAuthConfig)

    model_config = ConfigDict(use_enum_values=True)

    @field_validator("name", "description")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        return reject_unsafe_text(value)


class ApplicationCredentialModel(BaseModel):
    app_id: str
    hashed_secret: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: StatusEnum = StatusEnum.ACTIVE

    model_config = ConfigDict(use_enum_values=True)
