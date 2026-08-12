import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.repositories.application import ApplicationRepository
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.user import UserRepository
from app.schemas.refresh_token import RefreshTokenModel
from app.schemas.user import UserCreate, UserModel
from app.services.key_manager import key_manager


class AuthService:
    def __init__(self, user_repo: UserRepository, refresh_token_repo: RefreshTokenRepository, app_repo: ApplicationRepository):
        """
        Initializes the AuthService.
        """
        self.user_repo = user_repo
        self.refresh_token_repo = refresh_token_repo
        self.app_repo = app_repo

    async def signup(self, app_id: str, user_in: UserCreate):
        """
        Registers a new user for a specific application tenant.
        """
        app_check = await self.app_repo.get_by_client_id(app_id)
        if not app_check:
            raise HTTPException(status_code=403, detail="Invalid application context")

        existing = await self.user_repo.get_by_email(app_id, user_in.email)
        if existing:
            raise HTTPException(status_code=400, detail="User already exists")

        hashed = get_password_hash(user_in.password)
        user_data = UserModel(
            app_id=app_id, 
            email=user_in.email.lower(), 
            hashed_password=hashed,
            username=user_in.username,
            first_name=user_in.first_name,
            last_name=user_in.last_name
        ).model_dump()
        created = await self.user_repo.create(user_data, id=uuid.uuid4().hex)
        return created

    async def login(self, app_id: str, user_in: UserCreate):
        """
        Authenticates a user and issues a standard User JWT.
        """
        app_check = await self.app_repo.get_by_client_id(app_id)
        if not app_check:
            raise HTTPException(status_code=403, detail="Invalid application context")

        user = await self.user_repo.get_by_email(app_id, user_in.email)
        if not user or not verify_password(user_in.password, user["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create JWT
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=settings.jwt_expiration_minutes)
        payload = {
            "iss": settings.jwt_issuer,
            "sub": user["id"],
            "aud": "application_api",
            "app_id": app_id,
            "type": "user",
            "roles": user.get("roles", []),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": uuid.uuid4().hex,
        }

        token = key_manager.sign_jwt(payload)

        # Generate Refresh Token
        refresh_data = RefreshTokenModel(
            user_id=user["id"],
            app_id=app_id,
            expires_at=(now + timedelta(days=7)).isoformat()
        )
        await self.refresh_token_repo.create(refresh_data.model_dump())

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": settings.jwt_expiration_minutes * 60,
            "refresh_token": refresh_data.token
        }

    def generate_service_token(self, app_id: str, audience: str):
        """
        Generates a short-lived Service JWT for app-to-app authentication.
        """
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=settings.jwt_expiration_minutes)
        payload = {
            "iss": settings.jwt_issuer,
            "sub": f"service:{app_id}",
            "aud": audience,
            "app_id": app_id,
            "type": "service",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": uuid.uuid4().hex,
        }
        token = key_manager.sign_jwt(payload)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": settings.jwt_expiration_minutes * 60,
        }

    async def refresh_access_token(self, refresh_token: str):
        """
        Validates a refresh token, revokes it (token rotation), and issues a new token pair.
        """
        token_doc = await self.refresh_token_repo.get_by_token(refresh_token)
        if not token_doc:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
            
        # Check expiration
        expires_at = datetime.fromisoformat(token_doc["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            await self.refresh_token_repo.revoke_token(token_doc["id"])
            raise HTTPException(status_code=401, detail="Refresh token expired")
            
        # Get user
        user = await self.user_repo.get_tenant_resource(token_doc["app_id"], token_doc["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="User no longer exists")
            
        # Revoke the old token
        await self.refresh_token_repo.revoke_token(token_doc["id"])
        
        # Issue new tokens
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=settings.jwt_expiration_minutes)
        payload = {
            "iss": settings.jwt_issuer,
            "sub": user["id"],
            "aud": "application_api",
            "app_id": user["app_id"],
            "type": "user",
            "roles": user.get("roles", []),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": uuid.uuid4().hex,
        }
        new_access_token = key_manager.sign_jwt(payload)
        
        new_refresh_data = RefreshTokenModel(
            user_id=user["id"],
            app_id=user["app_id"],
            expires_at=(now + timedelta(days=7)).isoformat()
        )
        await self.refresh_token_repo.create(new_refresh_data.model_dump())
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_expiration_minutes * 60,
            "refresh_token": new_refresh_data.token
        }
