import pytest
from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import REDIRECT_URI, create_application


@pytest.mark.asyncio
async def test_unauthorized_application_creation(async_client: AsyncClient):
    response = await async_client.post("/api/v1/admin/applications",
        json={"name": "Test App"},
        headers={"x-admin-token": "wrong_token"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid admin token"


@pytest.mark.asyncio
async def test_authorized_application_creation(async_client: AsyncClient):
    response = await async_client.post("/api/v1/admin/applications",
        json={"name": "Test App"},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert response.status_code == 200
    data = response.json()
    assert "client_id" in data
    assert "client_secret" in data


@pytest.mark.asyncio
async def test_application_config_defaults(async_client: AsyncClient):
    """
    Existing applications (created without configuration) must remain valid
    and expose backwards-compatible defaults.
    """
    app_data = await create_application(async_client)

    resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
    assert resp.status_code == 200
    config = resp.json()
    assert config["name"] == app_data["name"]
    assert config["allow_signup"] is True
    assert config["allow_password_login"] is True
    assert config["require_email_verification"] is False
    assert config["allowed_scopes"] == ["openid", "profile", "email"]
    assert config.get("client_type") is None
    assert "client_secret" not in config
    assert "redirect_uris" not in config
    assert config["logo_url"] is None
    assert config["primary_color"] is None
    assert config["themes"] == ["light", "dark"]
    assert "theme" not in config


@pytest.mark.asyncio
async def test_application_config_persisted(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "branding": {
                "logo_url": "https://cdn.example.com/logo.png",
                "primary_color": "#112233",
                "secondary_color": "#445566",
            },
            "authentication": {
                "allow_signup": False,
                "allow_password_login": True,
                "require_email_verification": True,
            },
            "oauth": {
                "redirect_uris": [REDIRECT_URI, "http://localhost:3000/callback"],
                "allowed_scopes": ["openid", "email"],
                "allowed_grants": ["authorization_code"],
            },
        },
    )

    resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
    config = resp.json()
    assert config["logo_url"] == "https://cdn.example.com/logo.png"
    assert config["primary_color"] == "#112233"
    assert config["secondary_color"] == "#445566"
    assert config["allow_signup"] is False
    assert config["require_email_verification"] is True
    assert config["allowed_scopes"] == ["openid", "email"]


@pytest.mark.asyncio
async def test_application_config_validation_rejects_dangerous_values(async_client: AsyncClient):
    app_data = await create_application(async_client)

    cases = [
        {"branding": {"logo_url": "javascript:alert(1)"}},
        {"branding": {"primary_color": "red"}},
        {"oauth": {"redirect_uris": ["https://evil.example.com/*"]}},
        {"oauth": {"redirect_uris": ["javascript:alert(1)"]}},
        {"oauth": {"redirect_uris": ["data:text/html,<script>"]}},
        {"oauth": {"redirect_uris": ["file:///etc/passwd"]}},
        {"oauth": {"redirect_uris": ["https://example.com/cb#fragment"]}},
        {"oauth": {"redirect_uris": ["http://notlocalhost.example.com/cb"]}},
        {"oauth": {"allowed_scopes": ["admin:everything"]}},
        {"oauth": {"allowed_scopes": ["offline_access"]}},
        {"oauth": {"allowed_grants": ["password"]}},
        {"name": "<script>alert(1)</script>"},
        {"description": "ok <img src=x onerror=alert(1)>"},
        {"client_type": "trusted"},
    ]
    for case in cases:
        resp = await async_client.patch(f"/api/v1/admin/applications/{app_data['client_id']}/configuration",
            json=case,
            headers={"x-admin-token": settings.admin_secret},
        )
        assert resp.status_code == 422, f"{case} should be rejected: {resp.text}"


@pytest.mark.asyncio
async def test_application_config_admin_required(async_client: AsyncClient):
    app_data = await create_application(async_client)
    for headers in ({}, {"x-admin-token": "wrong_token"}):
        resp = await async_client.patch(f"/api/v1/admin/applications/{app_data['client_id']}/configuration",
            json={"branding": {"primary_color": "#000000"}},
            headers=headers,
        )
        assert resp.status_code in (403, 422), resp.text
        config_resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
        assert config_resp.json()["primary_color"] is None


@pytest.mark.asyncio
async def test_application_config_partial_update_merges(async_client: AsyncClient):
    app_data = await create_application(async_client)
    client_id = app_data["client_id"]

    # First update: branding only
    resp = await async_client.patch(f"/api/v1/admin/applications/{client_id}/configuration",
        json={"branding": {"primary_color": "#aabbcc"}},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert resp.status_code == 200

    # Second update: authentication only - branding must survive
    resp = await async_client.patch(f"/api/v1/admin/applications/{client_id}/configuration",
        json={"authentication": {"allow_signup": False}},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert resp.status_code == 200

    config = (await async_client.get(f"/api/v1/applications/{client_id}/configuration")).json()
    assert config["primary_color"] == "#aabbcc"
    assert config["allow_signup"] is False
    assert config["allow_password_login"] is True


@pytest.mark.asyncio
async def test_public_configuration_unknown_client(async_client: AsyncClient):
    resp = await async_client.get("/api/v1/applications/nonexistent/configuration")
    assert resp.status_code == 404
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_application_theme_configuration(async_client: AsyncClient):
    # App created with explicit light theme
    app_light = await create_application(
        async_client,
        config={"branding": {"themes": ["light"]}},
    )
    conf_light = (await async_client.get(f"/api/v1/applications/{app_light['client_id']}/configuration")).json()
    assert conf_light["themes"] == ["light"]
    assert "theme" not in conf_light

    # App created with top-level theme alias
    app_dark = await create_application(
        async_client,
        config={"theme": ["dark"]},
    )
    conf_dark = (await async_client.get(f"/api/v1/applications/{app_dark['client_id']}/configuration")).json()
    assert conf_dark["themes"] == ["dark"]
    assert "theme" not in conf_dark

    # Updating theme via PATCH
    update_resp = await async_client.patch(
        f"/api/v1/admin/applications/{app_light['client_id']}/configuration",
        json={"branding": {"themes": ["dark", "light"]}},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert update_resp.status_code == 200
    conf_updated = (await async_client.get(f"/api/v1/applications/{app_light['client_id']}/configuration")).json()
    assert set(conf_updated["themes"]) == {"light", "dark"}

    # Invalid theme rejected
    bad_resp = await async_client.patch(
        f"/api/v1/admin/applications/{app_light['client_id']}/configuration",
        json={"branding": {"themes": ["neon"]}},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert bad_resp.status_code == 422

