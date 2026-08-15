from fastapi import APIRouter, Depends, Form, Header, HTTPException

from app.core.errors import OAuthError
from app.dependencies import get_app_service, get_auth_service, get_current_user
from app.schemas.auth import RefreshTokenRequest, Token
from app.schemas.user import UserCreate, UserResponse
from app.services.application import ApplicationService, get_app_oauth_config
from app.services.auth import AuthService

router = APIRouter()


@router.post("/signup", response_model=UserResponse)
async def signup(
    user_in: UserCreate, x_application_id: str = Header(...), service: AuthService = Depends(get_auth_service)
):
    """
    Creates a new user account tied to the specified application tenant.
    """
    return await service.signup(x_application_id, user_in)


@router.post("/login", response_model=Token)
async def login(
    user_in: UserCreate, x_application_id: str = Header(...), service: AuthService = Depends(get_auth_service)
):
    """
    Authenticates a user and issues a standard User JWT.
    """
    return await service.login(x_application_id, user_in)


@router.post("/refresh", response_model=Token)
async def refresh_token(request: RefreshTokenRequest, service: AuthService = Depends(get_auth_service)):
    """
    Validates a refresh token and issues a new access/refresh token pair.
    """
    return await service.refresh_access_token(request.refresh_token)


@router.post("/oauth/token", response_model=Token, tags=["OAuth"])
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    audience: str = Form(..., description="Target service audience"),
    auth_service: AuthService = Depends(get_auth_service),
    app_service: ApplicationService = Depends(get_app_service),
):
    """
    OAuth2 Client Credentials grant to authenticate an application
    and issue a Service JWT for app-to-app communication.
    """
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    app = await app_service.get_application_by_client_id(client_id)
    if not app or "client_credentials" not in get_app_oauth_config(app)["allowed_grants"]:
        raise OAuthError("unauthorized_client", "The client_credentials grant is not enabled for this application")

    app_id = await app_service.verify_client_credentials(client_id, client_secret)
    return auth_service.generate_service_token(app_id, audience=audience)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Returns the details of the currently authenticated user.
    """
    return current_user
