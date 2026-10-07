from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse

from app.core.errors import OAuthError
from app.dependencies import get_app_service, get_oauth_service
from app.schemas.auth import Token
from app.schemas.oauth import AuthorizationRequest
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
    hosted Identity UI with a session ID. The application configuration
    is never placed in the redirect URL; the UI loads it via the session.
    """
    redirect_uri = req.redirect_uri
    app = await service.resolve_client(req.client_id)
    service.validate_redirect(app, req.redirect_uri)

    try:
        tx = await service.create_session(req)
    except OAuthError as exc:
        return RedirectResponse(
            url=service.build_error_redirect(redirect_uri, req.state, exc.error, exc.error_description),
            status_code=302,
        )

    return RedirectResponse(url=service.build_identity_ui_redirect(tx.id), status_code=302)


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
