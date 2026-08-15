from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse

from app.core.errors import OAuthError
from app.dependencies import get_app_service, get_oauth_service, verify_admin
from app.schemas.auth import Token
from app.schemas.oauth import (
    AuthorizationRequest,
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
    VerifyEmailRequest,
)
from app.schemas.oauth_transaction import OAuthTransactionResponse
from app.services.application import ApplicationService
from app.services.oauth import OAuthService

router = APIRouter()


@router.get("/authorize")
async def authorize(
    req: AuthorizationRequest = Depends(),
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Standards-aligned OAuth 2.0 authorization entrypoint.

    Validates the authorization request and redirects the browser to the
    hosted Identity UI with a transaction ID. The application configuration
    is never placed in the redirect URL; the UI loads it via the transaction.
    """
    redirect_uri = req.redirect_uri
    app = await service.resolve_client(req.client_id)
    service.validate_redirect(app, req.redirect_uri)

    try:
        tx = await service.create_transaction(req)
    except OAuthError as exc:
        return RedirectResponse(
            url=service.build_error_redirect(redirect_uri, req.state, exc.error, exc.error_description),
            status_code=302,
        )

    return RedirectResponse(url=service.build_identity_ui_redirect(tx.id), status_code=302)


@router.post("/transactions", response_model=dict, dependencies=[Depends(verify_admin)])
async def create_transaction(
    req: AuthorizationRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Internal (admin-protected) transaction creation endpoint.

    Performs the same validation as /authorize but returns the transaction
    directly instead of redirecting the browser.
    """
    tx = await service.create_transaction(req)
    return {"transaction_id": tx.id, "status": tx.status}


@router.get("/transactions/{transaction_id}", response_model=OAuthTransactionResponse)
async def load_transaction(transaction_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Loads safe transaction context for the hosted Identity UI.

    Contains only what the UI needs to render: transaction status, scopes,
    and public application branding/configuration.
    """
    return await service.load_transaction(transaction_id)


@router.post("/transactions/{transaction_id}/login")
async def transaction_login(
    transaction_id: str,
    body: LoginRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Transaction-bound login.

    Authenticates the user within the transaction's application and either
    returns the callback redirect URL (with a fresh authorization code) or
    signals that email verification is required.
    """
    return await service.login(transaction_id, body.email, body.password)


@router.post("/transactions/{transaction_id}/signup")
async def transaction_signup(
    transaction_id: str,
    body: SignupRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Transaction-bound signup.

    Creates the user within the transaction's application when signup is
    enabled, then proceeds toward authorization-code issuance.
    """
    return await service.signup(transaction_id, body)


@router.post("/transactions/{transaction_id}/forgot-password")
async def transaction_forgot_password(
    transaction_id: str,
    body: ForgotPasswordRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Transaction-bound password reset initiation.

    Enumeration-safe: the response is identical whether or not the email
    has an account. Reset tokens are delivered only by email.
    """
    return await service.forgot_password(transaction_id, body.email)


@router.post("/transactions/{transaction_id}/reset-password")
async def transaction_reset_password(
    transaction_id: str,
    body: ResetPasswordRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Transaction-bound password reset completion.

    The transaction provides application context; the reset token carries
    its own independent lifecycle.
    """
    return await service.reset_password(transaction_id, body.reset_token, body.new_password)


@router.post("/transactions/{transaction_id}/verify-email")
async def transaction_verify_email(
    transaction_id: str,
    body: VerifyEmailRequest,
    service: OAuthService = Depends(get_oauth_service),
):
    """
    Verifies the email of the user associated with the transaction and
    proceeds toward authorization-code issuance.
    """
    return await service.verify_email(transaction_id, body.verification_token)


@router.post("/transactions/{transaction_id}/cancel")
async def transaction_cancel(transaction_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Cancels an authorization transaction (user aborted authentication).
    """
    return await service.cancel_transaction(transaction_id)


@router.post("/token", response_model=Token, tags=["OAuth"])
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    audience: str | None = Form(None),
    oauth_service: OAuthService = Depends(get_oauth_service),
    app_service: ApplicationService = Depends(get_app_service),
):
    """
    Standards-aligned OAuth 2.0 token endpoint.

    Supports:
    - grant_type=authorization_code (PKCE required, interactive user tokens)
    - grant_type=client_credentials (service tokens, unchanged)
    """
    if grant_type == "client_credentials":
        if not client_secret:
            raise OAuthError("invalid_client", "client_secret is required")
        if not audience:
            raise OAuthError("invalid_request", "audience is required for client_credentials")
        app = await oauth_service.resolve_client(client_id)
        oauth_service.validate_grant_allowed(app, "client_credentials")
        try:
            app_id = await app_service.verify_client_credentials(client_id, client_secret)
        except HTTPException as exc:
            raise OAuthError("invalid_client", "Invalid client credentials", status_code=401) from exc
        return oauth_service.auth_service.generate_service_token(app_id, audience=audience)

    if grant_type == "authorization_code":
        if not code or not redirect_uri or not code_verifier:
            raise OAuthError(
                "invalid_request",
                "code, redirect_uri, and code_verifier are required for authorization_code",
            )
        return await oauth_service.exchange_authorization_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_secret=client_secret,
        )

    raise OAuthError("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")


@router.get("/applications/{client_id}/configuration", response_model=dict)
async def public_application_configuration(client_id: str, service: OAuthService = Depends(get_oauth_service)):
    """
    Public application configuration for the hosted Identity UI.

    Contains branding and authentication options only. Never exposes
    client secrets, redirect URIs, or administrative configuration.
    """
    config = await service.get_public_configuration(client_id)
    return config.model_dump(mode="json")


@router.post("/password/reset")
async def standalone_password_reset(body: ResetPasswordRequest, service: OAuthService = Depends(get_oauth_service)):
    """
    Standalone password reset used when the email link is opened outside an
    active authorization transaction.
    """
    return await service.reset_password_standalone(body.reset_token, body.new_password)
