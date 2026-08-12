from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.database import get_db_client, init_db
from app.routers import well_known
from app.routers.api.v1 import applications, auth


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

app.include_router(well_known.router)
app.include_router(applications.router, prefix="/api/v1/applications", tags=["Applications"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])

@app.get("/health")
async def health():
    """
    Health check endpoint to verify service liveness.
    """
    return {"status": "ok"}