from fastapi import APIRouter, Depends

from app.dependencies import get_app_service, get_oauth_service, verify_admin
from app.schemas.application import (
    ApplicationConfigUpdate,
    ApplicationCreate,
    ApplicationCredentials,
)
from app.schemas.oauth import AuthorizationRequest
from app.services.application import ApplicationService
from app.services.oauth import OAuthService

router = APIRouter(dependencies=[Depends(verify_admin)])

@router.post("/applications", response_model=ApplicationCredentials)
async def create_application(app_in: ApplicationCreate, service: ApplicationService = Depends(get_app_service)):
    """
    Registers a new consuming application and returns its initial client_id and client_secret.
    """
    return await service.register_application(app_in)


@router.get("/applications/{client_id}")
async def get_application(
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


@router.patch("/applications/{client_id}/configuration")
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


@router.post("/auth-sessions", response_model=dict)
async def create_auth_session(
    req: AuthorizationRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Internal (admin-protected) auth session creation endpoint.

    Performs the same validation as /authorize but returns the session
    directly instead of redirecting the browser.
    """
    tx = await service.create_session(req)
    return {"session_id": tx.id, "status": tx.status}
