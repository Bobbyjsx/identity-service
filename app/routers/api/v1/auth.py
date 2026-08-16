from fastapi import APIRouter, Depends, Header, HTTPException

from app.dependencies import get_auth_service, get_current_user, get_oauth_service
from app.schemas.auth import RefreshTokenRequest, Token
from app.schemas.oauth import ResetPasswordRequest
from app.schemas.user import UserCreate, UserResponse
from app.services.auth import AuthService
from app.services.oauth import OAuthService

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


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Returns the details of the currently authenticated user.
    """
    return current_user


@router.post("/password/reset")
async def standalone_password_reset(body: ResetPasswordRequest, service: OAuthService = Depends(get_oauth_service)):
    """
    Standalone password reset used when the email link is opened outside an
    active authorization session.
    """
    return await service.reset_password_standalone(body.reset_token, body.new_password)
