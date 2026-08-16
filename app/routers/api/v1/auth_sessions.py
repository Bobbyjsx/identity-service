from fastapi import APIRouter, Depends

from app.dependencies import get_oauth_service
from app.schemas.auth_session import AuthSessionResponse
from app.schemas.oauth import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
    VerifyEmailRequest,
)
from app.services.oauth import OAuthService

router = APIRouter()

@router.get("/{session_id}", response_model=AuthSessionResponse)
async def load_auth_session(session_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Loads safe auth session context for the hosted Identity UI.

    Contains only what the UI needs to render: session status, scopes,
    and public application branding/configuration.
    """
    return await service.load_session(session_id)


@router.post("/{session_id}/login")
async def session_login(
    session_id: str,
    body: LoginRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Session-bound login.

    Authenticates the user within the session's application and either
    returns the callback redirect URL (with a fresh authorization code) or
    signals that email verification is required.
    """
    return await service.login(session_id, body.email, body.password)


@router.post("/{session_id}/signup")
async def session_signup(
    session_id: str,
    body: SignupRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Session-bound signup.

    Creates the user within the session's application when signup is
    enabled, then proceeds toward authorization-code issuance.
    """
    return await service.signup(session_id, body)


@router.post("/{session_id}/forgot-password")
async def session_forgot_password(
    session_id: str,
    body: ForgotPasswordRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Session-bound password reset initiation.
    """
    return await service.forgot_password(session_id, body.email)


@router.post("/{session_id}/reset-password")
async def session_reset_password(
    session_id: str,
    body: ResetPasswordRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Session-bound password reset completion.
    """
    return await service.reset_password(session_id, body.reset_token, body.new_password)


@router.post("/{session_id}/verify-email")
async def session_verify_email(
    session_id: str,
    body: VerifyEmailRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Verifies the email of the user associated with the session and
    proceeds toward authorization-code issuance.
    """
    return await service.verify_email(session_id, body.verification_token)


@router.post("/{session_id}/resend-otp")
async def session_resend_otp(session_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Resends a fresh OTP to the user's email.

    Invalidates the previous OTP and resets the failed-attempt counter.
    Only valid while the session is in the `authenticated` state (user has
    logged in but not yet verified their email).
    """
    return await service.resend_otp(session_id)


@router.post("/{session_id}/cancel")
async def session_cancel(session_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Cancels an authorization session (user aborted authentication).
    """
    return await service.cancel_session(session_id)
