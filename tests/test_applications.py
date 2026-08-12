import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_unauthorized_application_creation(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/applications", 
        json={"name": "Test App"},
        headers={"x-admin-token": "wrong_token"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid admin token"

@pytest.mark.asyncio
async def test_authorized_application_creation(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/applications",
        json={"name": "Test App"},
        headers={"x-admin-token": settings.admin_secret}
    )
    assert response.status_code == 200
    data = response.json()
    assert "client_id" in data
    assert "client_secret" in data
