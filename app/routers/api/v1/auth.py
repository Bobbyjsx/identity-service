from fastapi import APIRouter, Depends, Form, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.cloud.firestore_v1.async_client import AsyncClient

from app.core.database import get_db
from app.repositories.application import (
    ApplicationCredentialRepository,
    ApplicationRepository,
)
from app.repositories.user import UserRepository
from app.repositories.refresh_token import RefreshTokenRepository
from app.schemas.auth import Token, RefreshTokenRequest
from app.schemas.user import UserCreate, UserResponse
from app.services.application import ApplicationService
from app.services.auth import AuthService
from app.services.key_manager import key_manager

router = APIRouter()
security = HTTPBearer()


def get_auth_service(db: AsyncClient = Depends(get_db)):
    """
    Dependency injection for AuthService.
    """
    return AuthService(UserRepository(db), RefreshTokenRepository(db))


def get_app_service(db: AsyncClient = Depends(get_db)):
    """
    Dependency injection for ApplicationService.
    """
    return ApplicationService(ApplicationRepository(db), ApplicationCredentialRepository(db))


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security), service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Extracts, verifies, and resolves the currently authenticated user from a JWT.
    """
    try:
        payload = key_manager.verify_jwt(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    app_id = payload.get("app_id")
    
    if not user_id or not app_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = await service.user_repo.get_tenant_resource(app_id, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


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
async def refresh_token(
    request: RefreshTokenRequest,
    service: AuthService = Depends(get_auth_service)
):
    """
    Validates a refresh token and issues a new access/refresh token pair.
    """
    return await service.refresh_access_token(request.refresh_token)


@router.post("/oauth/token", response_model=Token, tags=["OAuth"])
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service),
    app_service: ApplicationService = Depends(get_app_service),
):
    """
    OAuth2 Client Credentials grant to authenticate an application
    and issue a Service JWT for app-to-app communication.
    """
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    app_id = await app_service.verify_client_credentials(client_id, client_secret)
    return auth_service.generate_service_token(app_id)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Returns the details of the currently authenticated user.
    """
    return current_user
