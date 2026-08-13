from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.database import get_db_client, init_db
from app.routers import well_known
from app.routers.api.v1 import applications, auth, rbac


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
    lifespan=lifespan
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

app.include_router(well_known.router)
app.include_router(applications.router, prefix="/api/v1/applications", tags=["Applications"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(rbac.router, prefix="/api/v1")

@app.get("/health")
async def health():
    """
    Health check endpoint to verify service liveness.
    """
    return {"status": "ok"}