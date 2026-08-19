from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.cloud.firestore import AsyncClient

from app.core.config import settings
from app.core.database import get_db
from app.repositories.application import ApplicationCredentialRepository, ApplicationRepository
from app.repositories.auth_session import AuthSessionRepository
from app.repositories.authorization_code import AuthorizationCodeRepository
from app.repositories.permission import PermissionRepository
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.role import RoleRepository
from app.repositories.token import OpaqueTokenRepository
from app.repositories.user import UserRepository
from app.services.application import ApplicationService
from app.services.auth import AuthService
from app.services.notifications import LoggingNotificationService
from app.services.oauth import OAuthService
from app.services.rbac import RBACService

security = HTTPBearer()

def get_auth_service(db: AsyncClient = Depends(get_db)) -> AuthService:
    return AuthService(UserRepository(db), RefreshTokenRepository(db), ApplicationRepository(db))

def get_app_service(db: AsyncClient = Depends(get_db)) -> ApplicationService:
    return ApplicationService(ApplicationRepository(db), ApplicationCredentialRepository(db))

def get_oauth_service(db: AsyncClient = Depends(get_db)) -> OAuthService:
    return OAuthService(
        app_repo=ApplicationRepository(db),
        app_service=ApplicationService(ApplicationRepository(db), ApplicationCredentialRepository(db)),
        auth_service=AuthService(UserRepository(db), RefreshTokenRepository(db), ApplicationRepository(db)),
        user_repo=UserRepository(db),
        session_repo=AuthSessionRepository(db),
        code_repo=AuthorizationCodeRepository(db),
        reset_token_repo=OpaqueTokenRepository(db, "password_reset_tokens"),
        verification_token_repo=OpaqueTokenRepository(db, "email_verification_tokens"),
        notifications=LoggingNotificationService(),
    )

def get_rbac_service(db: AsyncClient = Depends(get_db)) -> RBACService:
    return RBACService(RoleRepository(db), PermissionRepository(db))

async def verify_admin(x_admin_token: str = Header(..., alias="X-Admin-Token")):
    """
    Validates that the provided X-Admin-Token header matches the secure bootstrap secret.
    """
    if x_admin_token != settings.admin_secret:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    return x_admin_token

async def verify_app(
    x_application_id: str = Header(..., alias="X-Application-Id"),
    db: AsyncClient = Depends(get_db)
) -> str:
    """
    Validates that the provided X-Application-Id exists and returns the internal app_id.
    """
    app_repo = ApplicationRepository(db)
    app = await app_repo.get_by_client_id(x_application_id)
    if not app:
        raise HTTPException(status_code=401, detail="Invalid application ID")
    return app["id"]

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    service: AuthService = Depends(get_auth_service)
) -> dict:
    from app.services.key_manager import key_manager
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
