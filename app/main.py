import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.database import get_db_client, init_db
from app.core.errors import OAuthError
from app.routers import well_known
from app.routers.api.v1 import applications, auth, oauth, rbac

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    Initializes Firestore and the Key Manager.
    """
    # Startup
    init_db()
    app.state.db_client = get_db_client()
    # Ensure key generation on startup if not exists
    from app.services.key_manager import key_manager

    await key_manager.initialize(app.state.db_client)
    yield
    # Shutdown
    app.state.db_client.close()


app = FastAPI(
    title="Identity Service",
    description="Standalone multi-tenant Identity Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(OAuthError)
async def oauth_error_handler(request: Request, exc: OAuthError):
    """
    Renders OAuth errors as {"error": ..., "error_description": ...}
    so OAuth clients and the hosted Identity UI can handle them programmatically.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.error_description},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Infrastructure and programming errors become a generic 500.
    Internal details (Firestore paths, stack frames) are logged, never returned.
    """
    if isinstance(exc, (StarletteHTTPException, RequestValidationError, OAuthError)):
        raise exc
    logger.exception("Unhandled server error")
    oauth_path = request.url.path.startswith("/api/v1/oauth") or request.url.path.startswith("/.well-known")
    if oauth_path:
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": "An unexpected error occurred"},
        )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(well_known.router)
app.include_router(applications.router, prefix="/api/v1/applications", tags=["Applications"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(oauth.router, prefix="/api/v1/oauth", tags=["OAuth"])
app.include_router(rbac.router, prefix="/api/v1")


@app.get("/health")
async def health():
    """
    Health check endpoint to verify service liveness.
    """
    return {"status": "ok"}
