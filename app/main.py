from fastapi import FastAPI

app = FastAPI(
    title="Identity Service",
    description="Standalone multi-tenant Identity Platform",
    version="1.0.0",
)

@app.get("/health")
async def health():
    """
    Health check endpoint to verify service liveness.
    """
    return {"status": "ok"}