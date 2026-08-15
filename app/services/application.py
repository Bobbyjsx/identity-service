import secrets
from typing import Any

from fastapi import HTTPException

from app.core.security import get_password_hash, verify_password
from app.repositories.application import (
    ApplicationCredentialRepository,
    ApplicationRepository,
)
from app.schemas.application import (
    DEFAULT_ALLOWED_GRANTS,
    DEFAULT_ALLOWED_SCOPES,
    DEFAULT_CLIENT_TYPE,
    KNOWN_OAUTH_SCOPES,
    ApplicationAuthenticationConfig,
    ApplicationBranding,
    ApplicationCreate,
    ApplicationCredentialModel,
    ApplicationCredentials,
    ApplicationModel,
    ApplicationOAuthConfig,
)
from app.schemas.enums import StatusEnum


def get_app_branding(app: dict[str, Any]) -> dict:
    """Returns application branding with backwards-compatible defaults."""
    branding = app.get("branding") or {}
    return {
        "logo_url": branding.get("logo_url"),
        "primary_color": branding.get("primary_color"),
        "secondary_color": branding.get("secondary_color"),
    }


def get_app_authentication_config(app: dict[str, Any]) -> dict:
    """Returns application authentication configuration with backwards-compatible defaults."""
    auth_config = app.get("authentication") or {}
    return {
        "allow_signup": auth_config.get("allow_signup", True),
        "allow_password_login": auth_config.get("allow_password_login", True),
        "require_email_verification": auth_config.get("require_email_verification", False),
    }


def get_app_oauth_config(app: dict[str, Any]) -> dict:
    """Returns application OAuth configuration with backwards-compatible defaults."""
    oauth = app.get("oauth") or {}
    raw_scopes = oauth.get("allowed_scopes", DEFAULT_ALLOWED_SCOPES)
    return {
        "redirect_uris": oauth.get("redirect_uris", []),
        "allowed_scopes": [s for s in raw_scopes if s in KNOWN_OAUTH_SCOPES],
        "allowed_grants": oauth.get("allowed_grants", DEFAULT_ALLOWED_GRANTS),
    }


def get_app_client_type(app: dict[str, Any]) -> str:
    """Existing applications without client_type are treated as public."""
    return app.get("client_type") or DEFAULT_CLIENT_TYPE


class ApplicationService:
    def __init__(self, app_repo: ApplicationRepository, cred_repo: ApplicationCredentialRepository):
        self.app_repo = app_repo
        self.cred_repo = cred_repo

    async def register_application(self, app_in: ApplicationCreate) -> ApplicationCredentials:
        """
        Registers a new application and generates a client ID and secret.
        Optional branding, authentication, OAuth, and client_type are stored
        atomically with the application document.
        """
        app_data = ApplicationModel(
            name=app_in.name,
            description=app_in.description,
            client_type=app_in.client_type,
            branding=app_in.branding or ApplicationBranding(),
            authentication=app_in.authentication or ApplicationAuthenticationConfig(),
            oauth=app_in.oauth or ApplicationOAuthConfig(),
        ).model_dump(mode="json")
        created_app = await self.app_repo.create(app_data)

        client_secret = secrets.token_urlsafe(32)
        hashed_secret = get_password_hash(client_secret)

        cred_data = ApplicationCredentialModel(app_id=created_app["id"], hashed_secret=hashed_secret).model_dump()
        await self.cred_repo.create(cred_data)

        return ApplicationCredentials(
            client_id=created_app["client_id"],
            client_secret=client_secret,
        )

    async def get_application_by_client_id(self, client_id: str) -> dict[str, Any] | None:
        return await self.app_repo.get_by_client_id(client_id)

    async def update_application_config(self, client_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """
        Applies a partial (merge) configuration update to an application document.

        Only known configuration namespaces are touched; existing values are
        preserved for fields that were not supplied.
        """
        app = await self.app_repo.get_by_client_id(client_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")

        doc_ref = self.app_repo.collection.document(app["id"])

        patch: dict[str, Any] = {}
        for namespace in ("branding", "authentication", "oauth"):
            incoming = (updates or {}).get(namespace)
            if incoming is not None:
                merged = dict(app.get(namespace) or {})
                merged.update(incoming)
                patch[namespace] = merged
        for field in ("name", "description", "client_type"):
            if (updates or {}).get(field) is not None:
                patch[field] = updates[field]

        if patch:
            await doc_ref.update(patch)
        return await self.app_repo.get(app["id"]) or app

    async def verify_client_credentials(self, client_id: str, client_secret: str) -> str:
        """
        Verifies an application's client credentials and returns the app_id if valid.
        """
        app = await self.app_repo.get_by_client_id(client_id)
        if not app:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        creds = await self.cred_repo.get_by_field("app_id", app["id"])
        for cred in creds:
            if cred.get("status") == StatusEnum.ACTIVE.value and verify_password(client_secret, cred["hashed_secret"]):
                return app["id"]

        raise HTTPException(status_code=401, detail="Invalid client credentials")
