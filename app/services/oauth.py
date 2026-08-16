import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from fastapi import HTTPException
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud.firestore_v1.transforms import Increment

from app.core.config import settings
from app.core.errors import OAuthError
from app.core.security import get_password_hash, hash_token
from app.repositories.application import ApplicationRepository
from app.repositories.authorization_code import AuthorizationCodeRepository
from app.repositories.auth_session import AuthSessionRepository
from app.repositories.token import OpaqueTokenRepository
from app.repositories.user import UserRepository
from app.schemas.application import (
    KNOWN_OAUTH_SCOPES,
    PublicApplicationConfig,
)
from app.schemas.authorization_code import (
    AuthorizationCodeModel,
    generate_authorization_code,
)
from app.schemas.email_verification import EmailVerificationTokenModel
from app.schemas.oauth import AuthorizationRequest, SignupRequest
from app.schemas.auth_session import AuthSessionModel
from app.schemas.password_reset import PasswordResetTokenModel
from app.schemas.user import UserCreate
from app.services.application import (
    get_app_authentication_config,
    get_app_branding,
    get_app_client_type,
    get_app_oauth_config,
)
from app.services.auth import AuthService
from app.services.key_manager import key_manager
from app.services.notifications import NotificationService

ACTIVE_STATUS = "active"
TRANSACTION_STATUS_ERRORS = {
    "expired": "session_expired",
    "completed": "session_completed",
    "cancelled": "session_cancelled",
}


def generate_password_reset_token() -> str:
    """High-entropy opaque password reset token (only its hash is stored)."""
    return f"pr_{uuid.uuid4().hex}{uuid.uuid4().hex}"


def generate_verification_token() -> str:
    """Generates a 6-digit numeric OTP for email verification (only its hash is stored)."""
    return f"{secrets.randbelow(900000) + 100000}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def pkce_verifier_to_challenge(code_verifier: str) -> str:
    """Computes the S256 PKCE challenge for a given code verifier."""
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


class OAuthService:
    def __init__(
        self,
        app_repo: ApplicationRepository,
        app_service: Any,
        auth_service: AuthService,
        user_repo: UserRepository,
        session_repo: AuthSessionRepository,
        code_repo: AuthorizationCodeRepository,
        reset_token_repo: OpaqueTokenRepository,
        verification_token_repo: OpaqueTokenRepository,
        notifications: NotificationService,
    ):
        self.app_repo = app_repo
        self.app_service = app_service
        self.auth_service = auth_service
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.code_repo = code_repo
        self.reset_token_repo = reset_token_repo
        self.verification_token_repo = verification_token_repo
        self.notifications = notifications

    # ------------------------------------------------------------------
    # Authorization request validation
    # ------------------------------------------------------------------

    async def resolve_client(self, client_id: str) -> dict[str, Any]:
        """
        Resolves and validates the application for a client_id.
        """
        app = await self.app_repo.get_by_client_id(client_id)
        if not app:
            raise OAuthError("invalid_client", "Unknown client_id", status_code=400)
        if app.get("status") != ACTIVE_STATUS:
            raise OAuthError("invalid_client", "Application is not active", status_code=400)
        return app

    def validate_redirect(self, app: dict[str, Any], redirect_uri: str):
        """
        Confirms the redirect URI is exactly registered for the application.

        Uses exact string comparison against the registered list. No
        wildcards, prefixes, or "contains" matching are ever used.
        """
        oauth_config = get_app_oauth_config(app)
        registered = oauth_config["redirect_uris"]
        if redirect_uri not in registered:
            raise OAuthError(
                "invalid_redirect_uri",
                "The redirect URI is not registered for this application",
                status_code=400,
            )

    def validate_response_type(self, response_type: str):
        if response_type != "code":
            raise OAuthError(
                "unsupported_response_type",
                "Only the authorization code response type is supported",
            )

    def validate_scopes(self, app: dict[str, Any], scopes: list[str]):
        oauth_config = get_app_oauth_config(app)
        allowed = set(oauth_config["allowed_scopes"]) & KNOWN_OAUTH_SCOPES
        invalid = [s for s in scopes if s not in allowed]
        if invalid:
            raise OAuthError(
                "invalid_scope",
                f"Requested scopes not allowed for this application: {', '.join(invalid)}",
            )

    def validate_grant_allowed(self, app: dict[str, Any], grant: str):
        oauth_config = get_app_oauth_config(app)
        if grant not in oauth_config["allowed_grants"]:
            raise OAuthError(
                "unauthorized_client",
                f"The {grant} grant is not enabled for this application",
            )

    async def create_session(self, req: AuthorizationRequest) -> AuthSessionModel:
        """
        Validates an authorization request and persists an OAuth session.
        """
        app = await self.resolve_client(req.client_id)
        self.validate_redirect(app, req.redirect_uri)
        self.validate_response_type(req.response_type)
        self.validate_grant_allowed(app, "authorization_code")

        scopes = [s for s in (req.scope or "").split(" ") if s]
        self.validate_scopes(app, scopes)

        expires_at = _now() + timedelta(minutes=settings.auth_session_expiration_minutes)
        tx = AuthSessionModel(
            application_id=app["id"],
            client_id=app["client_id"],
            redirect_uri=req.redirect_uri,
            response_type=req.response_type,
            scopes=scopes,
            state=req.state,
            code_challenge=req.code_challenge,
            code_challenge_method=req.code_challenge_method,
            nonce=req.nonce,
            expires_at=expires_at.isoformat(),
        )
        await self.session_repo.create(tx.model_dump(), id=tx.id)
        return tx

    def build_identity_ui_redirect(self, session_id: str) -> str:
        return f"{settings.identity_ui_base_url}/authorize?session_id={session_id}"

    def build_error_redirect(self, redirect_uri: str, state: str | None, error: str, error_description: str) -> str:
        params = {"error": error, "error_description": error_description}
        if state is not None:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{sep}{urlencode(params)}"

    # ------------------------------------------------------------------
    # Session loading / lifecycle
    # ------------------------------------------------------------------

    def effective_status(self, tx: dict[str, Any]) -> str:
        """
        Computes the effective session status, treating past-expiry
        sessions as expired.
        """
        if tx.get("status") in ("cancelled", "completed"):
            return tx["status"]
        try:
            expires_at = datetime.fromisoformat(tx["expires_at"])
        except (ValueError, TypeError):
            return "expired"
        if _now() > expires_at:
            return "expired"
        return tx.get("status") or "pending"

    async def load_session(self, session_id: str) -> dict[str, Any]:
        """
        Returns the safe session context for the hosted Identity UI.
        Never exposes secrets, state, challenges, or user data.
        """
        tx = await self.session_repo.get(session_id)
        if not tx:
            raise OAuthError("invalid_session", "Session not found", status_code=404)

        status = self.effective_status(tx)
        if status == "expired" and tx.get("status") != "expired":
            await self.session_repo.collection.document(tx["id"]).update({"status": "expired"})

        app = await self.app_repo.get(tx.get("application_id", ""))
        if not app:
            raise OAuthError("invalid_application", "Application not found", status_code=404)

        branding = get_app_branding(app)
        auth_config = get_app_authentication_config(app)
        application = {
            "name": app.get("name", "Unknown application"),
            "description": app.get("description"),
            "logo_url": branding["logo_url"],
            "logo_with_text": branding.get("logo_with_text"),
            "primary_color": branding["primary_color"],
            "secondary_color": branding["secondary_color"],
            "allow_signup": auth_config["allow_signup"],
            "allow_password_login": auth_config["allow_password_login"],
            "require_email_verification": auth_config["require_email_verification"],
        }

        result: dict[str, Any] = {
            "session_id": tx["id"],
            "status": status,
            "application": application,
            "scopes": tx.get("scopes", []),
            "redirect_url": None,
        }

        if status == "expired":
            result["redirect_url"] = self.build_error_redirect(
                tx["redirect_uri"],
                tx.get("state"),
                error="session_expired",
                error_description="The authorization session has expired",
            )
        elif status == "cancelled":
            result["redirect_url"] = self.build_error_redirect(
                tx["redirect_uri"],
                tx.get("state"),
                error="access_denied",
                error_description="The authorization request was cancelled",
            )

        return result

    async def cancel_session(self, session_id: str) -> dict[str, Any]:
        tx = await self.session_repo.get(session_id)
        if not tx:
            raise OAuthError("invalid_session", "Session not found", status_code=404)
        status = self.effective_status(tx)
        if status == "expired":
            raise OAuthError("session_expired", "Session has expired")
        if status not in {"pending", "authenticated"}:
            raise OAuthError(
                TRANSACTION_STATUS_ERRORS.get(status, "invalid_session_state"),
                f"Session is already {status}",
            )
        await self.session_repo.claim_session(
            session_id,
            expected_status={status},
            new_status="cancelled",
        )
        return {
            "session_id": session_id,
            "status": "cancelled",
            "redirect_url": self.build_error_redirect(
                tx["redirect_uri"],
                tx.get("state"),
                error="access_denied",
                error_description="The user cancelled the authorization request",
            ),
        }

    async def _load_session_for_operation(
        self, session_id: str, allowed_statuses: set[str] | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Validates a session is present, not expired, in an allowed state,
        and that its application is active. Returns (tx, app).
        """
        allowed_statuses = allowed_statuses or {"pending"}
        tx = await self.session_repo.get(session_id)
        if not tx:
            raise OAuthError("invalid_session", "Session not found", status_code=404)

        status = self.effective_status(tx)
        if status == "expired":
            raise OAuthError("session_expired", "Authorization session has expired")
        if status in TRANSACTION_STATUS_ERRORS:
            raise OAuthError(TRANSACTION_STATUS_ERRORS[status], f"Session is already {status}")
        if status == "authenticated" and "authenticated" not in allowed_statuses:
            raise OAuthError(
                "email_verification_required",
                "The user must verify their email before continuing",
            )
        if status not in allowed_statuses:
            raise OAuthError("invalid_session_state", "Operation not allowed in the current session state")

        app = await self.app_repo.get(tx.get("application_id", ""))
        if not app or app.get("status") != ACTIVE_STATUS:
            raise OAuthError("invalid_application", "Application is not active")
        return tx, app

    # ------------------------------------------------------------------
    # Authentication orchestration
    # ------------------------------------------------------------------

    def _require_password_login(self, app: dict[str, Any]):
        auth_config = get_app_authentication_config(app)
        if not auth_config["allow_password_login"]:
            raise OAuthError("password_login_disabled", "Password login is disabled for this application")

    async def login(self, session_id: str, email: str, password: str) -> dict[str, Any]:
        """
        Session-bound login. Authenticates the user within the
        session's application, then moves toward authorization-code
        issuance. Never returns tokens.
        """
        tx, app = await self._load_session_for_operation(session_id, {"pending"})
        self._require_password_login(app)

        try:
            user = await self.auth_service.authenticate_user(tx["client_id"], email, password)
        except HTTPException as exc:
            raise OAuthError(
                "invalid_credentials",
                "Invalid email or password",
                status_code=exc.status_code,
            ) from exc

        return await self._complete_authentication(tx, app, user)

    async def signup(self, session_id: str, signup_in: SignupRequest) -> dict[str, Any]:
        """
        Session-bound signup. Creates the user within the session's
        application (when allowed) and moves toward authorization-code
        issuance. Never returns tokens.
        """
        tx, app = await self._load_session_for_operation(session_id, {"pending"})

        user_in = UserCreate(
            email=signup_in.email,
            password=signup_in.password,
            username=signup_in.username,
            first_name=signup_in.first_name,
            last_name=signup_in.last_name,
        )
        try:
            user = await self.auth_service.create_user(tx["client_id"], user_in)
        except HTTPException as exc:
            error = "user_already_exists" if exc.status_code == 400 else "signup_disabled"
            raise OAuthError(
                error,
                str(exc.detail),
                status_code=exc.status_code,
            ) from exc

        return await self._complete_authentication(tx, app, user)

    async def _complete_authentication(
        self, tx: dict[str, Any], app: dict[str, Any], user: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Finishes the session-side of authentication.

        The pending → authenticated claim is atomic: only one concurrent
        login/signup can progress the session. Authorization codes are
        issued only after that claim succeeds.
        """
        auth_config = get_app_authentication_config(app)
        if auth_config["require_email_verification"] and not user.get("email_verified", False):
            claimed = await self.session_repo.claim_session(
                tx["id"],
                expected_status="pending",
                new_status="authenticated",
                updates={"user_id": user["id"]},
            )
            await self._issue_verification_token(claimed, app, user)
            return {"redirect_url": None, "email_verification_required": True}

        raw_code = await self.issue_authorization_code(tx, app, user, expected_status="pending")
        return {"redirect_url": self._build_callback_url(tx, raw_code), "email_verification_required": False}

    async def verify_email(self, session_id: str, verification_token: str) -> dict[str, Any]:
        """
        Verifies a user's email for a session awaiting verification,
        then issues the authorization code.

        Failed OTP attempts are counted on the session document. After 5
        wrong attempts the session is cancelled and the user must start a
        new login flow to receive a fresh OTP.
        """
        MAX_OTP_ATTEMPTS = 5

        tx, app = await self._load_session_for_operation(session_id, {"pending", "authenticated"})
        if not tx.get("user_id"):
            raise OAuthError("invalid_session_state", "No user is associated with this session")

        token = await self.verification_token_repo.get_by_token_hash(hash_token(verification_token))
        bound_correctly = (
            token is not None
            and token.get("app_id") == tx["client_id"]
            and token.get("user_id") == tx["user_id"]
        )

        if not bound_correctly:
            doc_ref = self.session_repo.collection.document(session_id)
            await doc_ref.update({"otp_attempts": Increment(1)})
            snap = await doc_ref.get()
            attempts = (snap.to_dict() or {}).get("otp_attempts", 1)
            if attempts >= MAX_OTP_ATTEMPTS:
                await doc_ref.update({"status": "cancelled"})
                raise OAuthError(
                    "otp_attempts_exceeded",
                    "Too many incorrect attempts. Please start a new login.",
                )
            raise OAuthError("invalid_verification_token", "Verification token is invalid")

        if self._token_expired(token):
            raise OAuthError("verification_token_expired", "Verification token has expired")
        if token.get("status") != "active":
            raise OAuthError("invalid_verification_token", "Verification token has already been used")

        user = await self.user_repo.get_tenant_resource(tx["client_id"], tx["user_id"])
        if not user:
            raise OAuthError("invalid_session_state", "User no longer exists")

        await self.user_repo.collection.document(user["id"]).update({"email_verified": True})
        await self.verification_token_repo.mark_used(token["id"], _now_iso())

        raw_code = await self.issue_authorization_code(tx, app, user)
        return {"redirect_url": self._build_callback_url(tx, raw_code)}

    async def resend_otp(self, session_id: str) -> dict[str, Any]:
        """
        Invalidates any existing active verification token for the session's
        user, resets the session's OTP attempt counter, and sends a fresh OTP.

        Only allowed while the session is still in the `authenticated` state
        (i.e. the user has logged in but not yet verified their email).
        """
        tx, app = await self._load_session_for_operation(session_id, {"authenticated"})
        if not tx.get("user_id"):
            raise OAuthError("invalid_session_state", "No user is associated with this session")

        user = await self.user_repo.get_tenant_resource(tx["client_id"], tx["user_id"])
        if not user:
            raise OAuthError("invalid_session_state", "User no longer exists")

        # Invalidate any still-active token for this user/app pair.
        async for doc in (
            self.verification_token_repo.collection
            .where(filter=FieldFilter("user_id", "==", tx["user_id"]))
            .where(filter=FieldFilter("app_id", "==", tx["client_id"]))
            .where(filter=FieldFilter("status", "==", "active"))
            .stream()
        ):
            await self.verification_token_repo.collection.document(doc.id).update({"status": "used"})

        # Reset OTP attempt counter on the session.
        await self.session_repo.collection.document(session_id).update({"otp_attempts": 0})

        # Issue and send a fresh OTP.
        await self._issue_verification_token(tx, app, user)
        return {"detail": "A new verification code has been sent to your email."}

    async def _issue_verification_token(self, tx: dict[str, Any], app: dict[str, Any], user: dict[str, Any]):
        raw_token = generate_verification_token()
        token = EmailVerificationTokenModel(
            token_hash=hash_token(raw_token),
            app_id=tx["client_id"],
            user_id=user["id"],
            expires_at=(_now() + timedelta(minutes=30)).isoformat(),
        )
        await self.verification_token_repo.create(token.model_dump(), id=token.id)
        await self.notifications.send_verification_email(
            to=user["email"], otp=raw_token, app_name=app.get("name", "Application")
        )

    # ------------------------------------------------------------------
    # Password reset
    # ------------------------------------------------------------------

    async def forgot_password(self, session_id: str, email: str) -> dict[str, Any]:
        """
        Initiates a password reset for the session's application.

        Enumeration-safe: returns the same response whether or not the email
        has an account. The reset token is only delivered by email.
        """
        tx, app = await self._load_session_for_operation(session_id, {"pending"})

        user = await self.user_repo.get_by_email(tx["client_id"], email)
        if user:
            raw_token = generate_password_reset_token()
            token = PasswordResetTokenModel(
                token_hash=hash_token(raw_token),
                app_id=tx["client_id"],
                user_id=user["id"],
                expires_at=(_now() + timedelta(minutes=settings.password_reset_token_expiration_minutes)).isoformat(),
            )
            await self.reset_token_repo.create(token.model_dump(), id=token.id)
            reset_url = f"{settings.identity_ui_base_url}/reset-password?token={raw_token}"
            await self.notifications.send_password_reset_email(
                to=user["email"], reset_url=reset_url, app_name=app.get("name", "Application")
            )

        return {"detail": "If the email has an account, a password reset link has been sent."}

    async def _load_reset_token(self, reset_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        token = await self.reset_token_repo.get_by_token_hash(hash_token(reset_token))
        if not token:
            raise OAuthError("invalid_reset_token", "Password reset token is invalid")
        if self._token_expired(token):
            raise OAuthError("reset_token_expired", "Password reset token has expired")
        if token.get("status") != "active":
            raise OAuthError("invalid_reset_token", "Password reset token has already been used")

        user = await self.user_repo.get_tenant_resource(token["app_id"], token["user_id"])
        if not user:
            raise OAuthError("invalid_reset_token", "Password reset token is invalid")
        return token, user

    def _token_expired(self, token: dict[str, Any]) -> bool:
        try:
            expires_at = datetime.fromisoformat(token["expires_at"])
        except (ValueError, TypeError):
            return True
        return _now() > expires_at

    async def _apply_password_reset(self, token: dict[str, Any], user: dict[str, Any], new_password: str):
        await self.user_repo.collection.document(user["id"]).update(
            {"hashed_password": get_password_hash(new_password)}
        )
        await self.reset_token_repo.mark_used(token["id"], _now_iso())
        await self.auth_service.refresh_token_repo.revoke_user_tokens(user["id"], user["app_id"])

    async def reset_password(self, session_id: str, reset_token: str, new_password: str) -> dict[str, Any]:
        """
        Session-bound password reset. The session provides application
        context; the reset token carries its own independent lifecycle.
        """
        tx, _ = await self._load_session_for_operation(session_id, {"pending"})
        token, user = await self._load_reset_token(reset_token)
        if token["app_id"] != tx["client_id"]:
            raise OAuthError("invalid_reset_token", "Password reset token does not match this session")
        await self._apply_password_reset(token, user, new_password)
        return {"detail": "Password has been reset. You can now sign in."}

    async def reset_password_standalone(self, reset_token: str, new_password: str) -> dict[str, Any]:
        """
        Standalone password reset used when the email link is opened outside
        an active authorization session.
        """
        token, user = await self._load_reset_token(reset_token)
        await self._apply_password_reset(token, user, new_password)
        return {"detail": "Password has been reset. You can now sign in."}

    # ------------------------------------------------------------------
    # Authorization code issuance
    # ------------------------------------------------------------------

    async def issue_authorization_code(
        self,
        tx: dict[str, Any],
        app: dict[str, Any],
        user: dict[str, Any],
        expected_status: str = "authenticated",
    ) -> str:
        """
        Creates a short-lived, single-use authorization code bound to the
        session, client, redirect URI, user, and PKCE challenge.
        Only the SHA-256 hash of the code is persisted.
        """
        raw_code = generate_authorization_code()
        code = AuthorizationCodeModel(
            code_hash=hash_token(raw_code),
            session_id=tx["id"],
            application_id=tx["application_id"],
            client_id=tx["client_id"],
            user_id=user["id"],
            redirect_uri=tx["redirect_uri"],
            scopes=tx.get("scopes", []),
            code_challenge=tx["code_challenge"],
            code_challenge_method=tx.get("code_challenge_method", "S256"),
            nonce=tx.get("nonce"),
            expires_at=(_now() + timedelta(minutes=settings.oauth_authorization_code_expiration_minutes)).isoformat(),
        )
        await self.session_repo.complete_with_code(
            session_id=tx["id"],
            expected_status=expected_status,
            session_updates={
                "status": "completed",
                "user_id": user["id"],
                "completed_at": _now_iso(),
            },
            code_collection=self.code_repo.collection,
            code_id=code.id,
            code_data=code.model_dump(),
        )
        return raw_code

    def _build_callback_url(self, tx: dict[str, Any], raw_code: str) -> str:
        params = {"code": raw_code}
        if tx.get("state") is not None:
            params["state"] = tx["state"]
        sep = "&" if "?" in tx["redirect_uri"] else "?"
        return f"{tx['redirect_uri']}{sep}{urlencode(params)}"

    # ------------------------------------------------------------------
    # Token exchange
    # ------------------------------------------------------------------

    async def exchange_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        """
        Exchanges an authorization code for tokens.

        All binding validations happen before any token is issued; the code
        is atomically marked used to prevent double redemption.
        """
        code_doc = await self.code_repo.get_by_code_hash(hash_token(code))
        if not code_doc:
            raise OAuthError("invalid_grant", "Invalid authorization code")

        if self._token_expired(code_doc):
            raise OAuthError("invalid_grant", "Authorization code has expired")
        if code_doc.get("status") != "active":
            raise OAuthError("invalid_grant", "Authorization code has already been used")
        if code_doc.get("client_id") != client_id:
            raise OAuthError("invalid_grant", "Authorization code was issued for a different client")
        if code_doc.get("redirect_uri") != redirect_uri:
            raise OAuthError("invalid_grant", "Redirect URI does not match the authorization request")

        app = await self.app_repo.get(code_doc.get("application_id", ""))
        if not app or app.get("status") != ACTIVE_STATUS:
            raise OAuthError("invalid_grant", "Application is not active")
        if code_doc.get("client_id") != app.get("client_id"):
            raise OAuthError("invalid_grant", "Authorization code does not match the application")

        oauth_config = get_app_oauth_config(app)
        if "authorization_code" not in oauth_config["allowed_grants"]:
            raise OAuthError("unauthorized_client", "The authorization code grant is not enabled for this application")

        client_type = get_app_client_type(app)
        if client_type == "confidential" and not client_secret:
            raise OAuthError("invalid_client", "client_secret is required for confidential clients", status_code=401)
        if client_secret:
            try:
                await self.app_service.verify_client_credentials(client_id, client_secret)
            except HTTPException as exc:
                raise OAuthError("invalid_client", "Invalid client credentials", status_code=401) from exc

        challenge = pkce_verifier_to_challenge(code_verifier)
        if challenge != code_doc.get("code_challenge"):
            raise OAuthError("invalid_grant", "PKCE verification failed")

        tx = await self.session_repo.get(code_doc["session_id"])
        if not tx:
            raise OAuthError("invalid_grant", "Authorization session not found")
        if tx.get("application_id") != code_doc.get("application_id"):
            raise OAuthError("invalid_grant", "Authorization session mismatch")
        if self.effective_status(tx) != "completed":
            raise OAuthError("invalid_grant", "Authorization session is not completed")

        user = await self.user_repo.get_tenant_resource(code_doc["client_id"], code_doc["user_id"])
        if not user:
            raise OAuthError("invalid_grant", "User no longer exists")

        used_at = _now_iso()
        try:
            redeemed = await self.code_repo.mark_used_atomic(code_doc["id"], code_doc["code_hash"], "active", used_at)
        except Exception as exc:
            raise OAuthError(
                "server_error",
                "An unexpected error occurred",
                status_code=500,
            ) from exc
        if not redeemed:
            raise OAuthError("invalid_grant", "Authorization code has already been used")

        scopes = code_doc.get("scopes", [])
        tokens = await self.auth_service.issue_user_tokens(user, client_id, scope=" ".join(scopes))

        if "openid" in scopes:
            tokens["id_token"] = self._build_id_token(user, code_doc, scopes)

        return tokens

    def _build_id_token(self, user: dict[str, Any], code_doc: dict[str, Any], scopes: list[str]) -> str:
        """
        Builds an OIDC ID token.

        Distinct from access tokens: audience is the client application, and
        only identity claims are included. Signed with the shared Ed25519 key.
        """
        now = _now()
        exp = now + timedelta(minutes=settings.jwt_expiration_minutes)
        claims: dict[str, Any] = {
            "iss": settings.identity_issuer,
            "sub": user["id"],
            "aud": code_doc["client_id"],
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": uuid.uuid4().hex,
        }
        if code_doc.get("nonce"):
            claims["nonce"] = code_doc["nonce"]
        if "email" in scopes:
            claims["email"] = user.get("email")
            claims["email_verified"] = bool(user.get("email_verified", False))
        if "profile" in scopes:
            first = user.get("first_name") or ""
            last = user.get("last_name") or ""
            if first or last:
                claims["name"] = f"{first} {last}".strip()
            if user.get("username"):
                claims["preferred_username"] = user["username"]
        return key_manager.sign_jwt(claims)

    # ------------------------------------------------------------------
    # Public application configuration
    # ------------------------------------------------------------------

    async def get_public_configuration(self, client_id: str) -> PublicApplicationConfig:
        """
        Safe public application configuration for the hosted Identity UI.

        Never exposes client secrets, credential hashes, registered redirect
        URIs, or administrative configuration.
        """
        app = await self.app_repo.get_by_client_id(client_id)
        if not app:
            raise OAuthError("invalid_client", "Unknown client_id", status_code=404)

        branding = get_app_branding(app)
        auth_config = get_app_authentication_config(app)
        oauth_config = get_app_oauth_config(app)
        return PublicApplicationConfig(
            name=app.get("name", "Unknown application"),
            description=app.get("description"),
            logo_url=branding["logo_url"],
            logo_with_text=branding.get("logo_with_text"),
            primary_color=branding["primary_color"],
            secondary_color=branding["secondary_color"],
            allow_signup=auth_config["allow_signup"],
            allow_password_login=auth_config["allow_password_login"],
            require_email_verification=auth_config["require_email_verification"],
            allowed_scopes=oauth_config["allowed_scopes"],
        )
