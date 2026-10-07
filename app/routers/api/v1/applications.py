from fastapi import APIRouter, Depends

from app.dependencies import get_oauth_service
from app.services.oauth import OAuthService

router = APIRouter()

@router.get("/{client_id}/configuration", response_model=dict)
async def public_application_configuration(client_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Public application configuration for the hosted Identity UI.

    Contains branding and authentication options only. Never exposes
    client secrets, redirect URIs, or administrative configuration.
    """
    config = await service.get_public_configuration(client_id)
    return config.model_dump(mode="json")
