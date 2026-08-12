import secrets

from fastapi import HTTPException

from app.core.security import get_password_hash, verify_password
from app.repositories.application import (
    ApplicationCredentialRepository,
    ApplicationRepository,
)
from app.schemas.application import (
    ApplicationCreate,
    ApplicationCredentialModel,
    ApplicationCredentials,
    ApplicationModel,
)
from app.schemas.enums import StatusEnum


class ApplicationService:
    def __init__(self, app_repo: ApplicationRepository, cred_repo: ApplicationCredentialRepository):
        """
        Initializes the ApplicationService.
        """
        self.app_repo = app_repo
        self.cred_repo = cred_repo

    async def register_application(self, app_in: ApplicationCreate) -> ApplicationCredentials:
        """
        Registers a new application and generates a client ID and secret.
        """
        app_data = ApplicationModel(name=app_in.name, description=app_in.description).model_dump()
        created_app = await self.app_repo.create(app_data)
        
        # Generate client secret
        client_secret = secrets.token_urlsafe(32)
        hashed_secret = get_password_hash(client_secret)
        
        cred_data = ApplicationCredentialModel(app_id=created_app["id"], hashed_secret=hashed_secret).model_dump()
        await self.cred_repo.create(cred_data)
        
        return ApplicationCredentials(
            client_id=created_app["client_id"],
            client_secret=client_secret  # Only shown once
        )

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
