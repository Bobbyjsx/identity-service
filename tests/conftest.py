import os

import pytest_asyncio
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from app.main import app

# Force Firestore to use the emulator
os.environ["FIRESTORE_EMULATOR_HOST"] = "127.0.0.1:8080"
os.environ["GOOGLE_CLOUD_PROJECT"] = "test-project"
os.environ["IDENTITY_ENVIRONMENT"] = "development"

@pytest_asyncio.fixture
async def async_client():
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
