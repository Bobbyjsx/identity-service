from fastapi import APIRouter, Depends
from google.cloud.firestore_v1.async_client import AsyncClient

from app.core.database import get_db
from app.repositories.application import (
    ApplicationCredentialRepository,
    ApplicationRepository,
)
from app.schemas.application import ApplicationCreate, ApplicationCredentials
from app.services.application import ApplicationService

router = APIRouter()

def get_app_service(db: AsyncClient = Depends(get_db)):
    """
    Dependency injection for ApplicationService.
    """
    return ApplicationService(ApplicationRepository(db), ApplicationCredentialRepository(db))

@router.post("", response_model=ApplicationCredentials)
async def create_application(app_in: ApplicationCreate, service: ApplicationService = Depends(get_app_service)):
    """
    Registers a new consuming application and returns its initial client_id and client_secret.
    """
    return await service.register_application(app_in)
