import jwt
import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_invalid_application_context_signup(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": "test@example.com", "password": "password123"},
        headers={"x-application-id": "invalid_app_id"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid application context"


@pytest.mark.asyncio
async def test_valid_signup_and_token_format(async_client: AsyncClient):
    # Create App
    app_resp = await async_client.post("/api/v1/admin/applications", json={"name": "Test App"}, headers={"x-admin-token": settings.admin_secret}
    )
    app_data = app_resp.json()
    client_id = app_data["client_id"]

    # Signup
    signup_resp = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": "test2@example.com", "password": "password123"},
        headers={"x-application-id": client_id},
    )
    assert signup_resp.status_code == 200

    # Login
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "test2@example.com", "password": "password123"},
        headers={"x-application-id": client_id},
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data

    access_token = token_data["access_token"]

    # Decode token without verification to inspect claims
    unverified_claims = jwt.decode(access_token, options={"verify_signature": False})

    assert unverified_claims["iss"] == settings.identity_issuer
    assert unverified_claims["type"] == "user"
    assert unverified_claims["aud"] == "application_api"


@pytest.mark.asyncio
async def test_service_token_audience(async_client: AsyncClient):
    # Create App
    app_resp = await async_client.post("/api/v1/admin/applications",
        json={
            "name": "Test App",
            "oauth": {"allowed_grants": ["authorization_code", "client_credentials"]},
        },
        headers={"x-admin-token": settings.admin_secret},
    )
    app_data = app_resp.json()
    client_id = app_data["client_id"]
    client_secret = app_data["client_secret"]

    # Get service token
    token_resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": "custom_file_service",
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()

    unverified_claims = jwt.decode(token_data["access_token"], options={"verify_signature": False})
    assert unverified_claims["iss"] == settings.identity_issuer
    assert unverified_claims["type"] == "service"
    assert unverified_claims["aud"] == "custom_file_service"
