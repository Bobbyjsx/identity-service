from fastapi import APIRouter, Depends

from app.dependencies import get_app_service, verify_admin
from app.schemas.application import ApplicationCreate, ApplicationCredentials
from app.services.application import ApplicationService

router = APIRouter()


@router.post("", response_model=ApplicationCredentials, dependencies=[Depends(verify_admin)])
async def create_application(app_in: ApplicationCreate, service: ApplicationService = Depends(get_app_service)):
    """
    Registers a new consuming application and returns its initial client_id and client_secret.
    """
    return await service.register_application(app_in)
