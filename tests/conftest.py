import base64
import hashlib
import os
import uuid

import pytest_asyncio
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from app.main import app

# Force Firestore to use the emulator
os.environ["FIRESTORE_EMULATOR_HOST"] = "127.0.0.1:8080"
os.environ["GOOGLE_CLOUD_PROJECT"] = "test-project"
os.environ["IDENTITY_ENVIRONMENT"] = "development"

REDIRECT_URI = "https://app.example.com/callback"


def pkce_pair(verifier: str | None = None) -> tuple[str, str]:
    """
    Returns a (code_verifier, code_challenge) pair using S256.
    """
    verifier = verifier or base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


@pytest_asyncio.fixture
async def async_client():
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


@pytest_asyncio.fixture
async def db():
    """
    Direct Firestore emulator client for inspecting/mutating test documents.
    """
    from app.core.database import get_db_client

    client = get_db_client()
    yield client
    client.close()


async def create_application(
    async_client: AsyncClient,
    name: str | None = None,
    config: dict | None = None,
) -> dict:
    """
    Creates an application via the admin API and optionally patches its
    hosted-login configuration. Returns the full application document
    (fetched via the admin detail endpoint) merged with credentials.
    """
    from app.core.config import settings

    app_name = name or f"Test App {uuid.uuid4().hex[:8]}"
    app_resp = await async_client.post(
        "/api/v1/applications",
        json={"name": app_name},
        headers={"x-admin-token": settings.admin_secret},
    )
    assert app_resp.status_code == 200, app_resp.text
    data = app_resp.json()

    if config:
        patch_resp = await async_client.patch(
            f"/api/v1/applications/{data['client_id']}/configuration",
            json=config,
            headers={"x-admin-token": settings.admin_secret},
        )
        assert patch_resp.status_code == 200, patch_resp.text

    detail_resp = await async_client.get(
        f"/api/v1/applications/{data['client_id']}/configuration",
        headers={"x-admin-token": settings.admin_secret},
    )
    detail = detail_resp.json()
    detail.update(data)
    return detail


def authorize_params(
    client_id: str,
    *,
    redirect_uri: str = REDIRECT_URI,
    scope: str = "openid profile email",
    state: str = "abc123",
    verifier: str | None = None,
    challenge_method: str = "S256",
    response_type: str = "code",
    **overrides,
) -> dict:
    """
    Builds a valid authorization request parameter set.
    """
    verifier, challenge = pkce_pair(verifier)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": challenge_method,
    }
    params.update(overrides)
    return params


async def authorize_and_get_transaction(
    async_client: AsyncClient, client_id: str, **overrides
) -> tuple[str, str, dict]:
    """
    Runs a full authorization request and returns
    (transaction_id, code_verifier, authorize response).
    """
    verifier, _ = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, **overrides)
    resp = await async_client.get("/api/v1/oauth/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert "/authorize?transaction_id=" in location
    tx_id = location.split("transaction_id=")[-1]
    return tx_id, verifier, resp


async def login_and_get_code(async_client: AsyncClient, tx_id: str, email: str, password: str) -> str:
    """
    Completes a transaction login and extracts the raw authorization code
    from the returned callback redirect URL.
    """
    resp = await async_client.post(
        f"/api/v1/oauth/transactions/{tx_id}/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("redirect_url")
    from urllib.parse import parse_qs, urlparse

    query = parse_qs(urlparse(data["redirect_url"]).query)
    assert "code" in query
    return query["code"][0]
