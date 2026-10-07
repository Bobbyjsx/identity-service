import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_rbac_flow(async_client: AsyncClient):
    # 1. Create an application
    app_resp = await async_client.post("/api/v1/admin/applications",
        json={"name": "Test App"},
        headers={"x-admin-token": settings.admin_secret}
    )
    app_data = app_resp.json()
    client_id = app_data["client_id"]

    # 2. Create permissions
    perm1_resp = await async_client.post(
        "/api/v1/rbac/permissions",
        json={"name": "read:documents", "description": "Read documents"},
        headers={"x-application-id": client_id}
    )
    assert perm1_resp.status_code == 200
    
    perm2_resp = await async_client.post(
        "/api/v1/rbac/permissions",
        json={"name": "write:documents", "description": "Write documents"},
        headers={"x-application-id": client_id}
    )
    assert perm2_resp.status_code == 200

    # 3. Create a role with a valid permission
    role_resp = await async_client.post(
        "/api/v1/rbac/roles",
        json={"name": "document_reader", "permissions": ["read:documents"]},
        headers={"x-application-id": client_id}
    )
    assert role_resp.status_code == 200
    assert "read:documents" in role_resp.json()["permissions"]

    # 4. Try to create a role with invalid permission
    role_invalid_resp = await async_client.post(
        "/api/v1/rbac/roles",
        json={"name": "document_writer", "permissions": ["delete:documents"]},
        headers={"x-application-id": client_id}
    )
    assert role_invalid_resp.status_code == 400
    assert "delete:documents does not exist" in role_invalid_resp.json()["detail"]

    # 5. List roles
    list_roles_resp = await async_client.get(
        "/api/v1/rbac/roles",
        headers={"x-application-id": client_id}
    )
    assert list_roles_resp.status_code == 200
    roles = list_roles_resp.json()
    assert len(roles) == 1
    assert roles[0]["name"] == "document_reader"
