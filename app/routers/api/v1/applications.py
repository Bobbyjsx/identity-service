from fastapi import APIRouter, Depends

from app.dependencies import get_app_service, verify_admin
from app.schemas.application import (
    ApplicationConfigUpdate,
    ApplicationCreate,
    ApplicationCredentials,
)
from app.services.application import ApplicationService

router = APIRouter()


@router.post("", response_model=ApplicationCredentials, dependencies=[Depends(verify_admin)])
async def create_application(app_in: ApplicationCreate, service: ApplicationService = Depends(get_app_service)):
    """
    Registers a new consuming application and returns its initial client_id and client_secret.
    """
    return await service.register_application(app_in)


@router.get("/{client_id}/configuration", dependencies=[Depends(verify_admin)])
async def get_application_configuration(
    client_id: str, service: ApplicationService = Depends(get_app_service)
):
    """
    Returns the full application document including hosted-login configuration.
    Admin-only; never includes the client secret (it is not stored).
    """
    app = await service.get_application_by_client_id(client_id)
    if not app:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Application not found")
    return app


@router.patch("/{client_id}/configuration", dependencies=[Depends(verify_admin)])
async def update_application_configuration(
    client_id: str,
    updates: ApplicationConfigUpdate,
    service: ApplicationService = Depends(get_app_service),
):
    """
    Partially updates an application's hosted-login configuration (branding,
    authentication, OAuth). Admin-only.
    """
    return await service.update_application_config(
        client_id, updates.model_dump(exclude_unset=True, exclude_none=True, mode="json")
    )
