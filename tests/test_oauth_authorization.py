import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import (
    REDIRECT_URI,
    authorize_and_get_transaction,
    authorize_params,
    create_application,
    login_and_get_code,
)


async def _expire_transaction(db, tx_id: str):
    """Forces a transaction's expiry timestamp into the past."""
    await (
        db.collection("auth_sessions")
        .document(tx_id)
        .update({"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()})
    )


@pytest.mark.asyncio
async def test_valid_authorization_request_redirects_to_identity_ui(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, resp = await authorize_and_get_transaction(async_client, app_data["client_id"])
    assert resp.headers["location"].startswith(f"{settings.identity_ui_base_url}/authorize?")

    # Transaction persisted with all required fields
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["client_id"] == app_data["client_id"]
    assert doc["redirect_uri"] == REDIRECT_URI
    assert doc["response_type"] == "code"
    assert doc["scopes"] == ["openid", "profile", "email"]
    assert doc["state"] == "abc123"
    assert doc["status"] == "pending"
    assert doc["code_challenge"]
    assert doc["code_challenge_method"] == "S256"
    assert doc["user_id"] is None


@pytest.mark.asyncio
async def test_authorize_unknown_client_rejected(async_client: AsyncClient):
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params("app_nonexistent"),
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_authorize_inactive_application_rejected(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    await db.collection("applications").document(app_data["id"]).update({"status": "inactive"})

    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"]),
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_authorize_localhost_http_redirect_allowed(async_client: AsyncClient):
    localhost = "http://localhost:3000/callback"
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [localhost]}})
    tx_id, _, resp = await authorize_and_get_transaction(async_client, app_data["client_id"], redirect_uri=localhost)
    assert resp.status_code == 302
    assert tx_id.startswith("tx_")


@pytest.mark.asyncio
async def test_authorize_unregistered_redirect_uri_rejected(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], redirect_uri="https://evil.example.com/callback"),
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_authorize_redirect_uri_exact_match_required(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    for tampered in (
        f"{REDIRECT_URI}/extra",
        "https://app.example.com/callback?foo=bar",
        "https://app.example.com/callbackx",
        REDIRECT_URI.replace("callback", "Callback"),
        f"https://app.example.com/{REDIRECT_URI}",
    ):
        resp = await async_client.get(
            "/api/v1/oauth/authorize",
            params=authorize_params(app_data["client_id"], redirect_uri=tampered),
            follow_redirects=False,
        )
        assert resp.status_code == 400, f"{tampered} should be rejected"
        assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_authorize_invalid_scope_redirects_with_error(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], scope="openid admin:everything"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlparse(location).query)
    assert query["error"][0] == "invalid_scope"
    assert query["state"][0] == "abc123"


@pytest.mark.asyncio
async def test_authorize_scope_not_allowed_by_application(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {
                "redirect_uris": [REDIRECT_URI],
                "allowed_scopes": ["openid"],
            }
        },
    )
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], scope="openid email"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert parse_qs(urlparse(resp.headers["location"]).query)["error"][0] == "invalid_scope"


@pytest.mark.asyncio
async def test_authorize_unsupported_response_type(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    # Implicit flow must not be supported
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], response_type="token"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert parse_qs(urlparse(resp.headers["location"]).query)["error"][0] == "unsupported_response_type"

    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], response_type="code id_token"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert parse_qs(urlparse(resp.headers["location"]).query)["error"][0] == "unsupported_response_type"


@pytest.mark.asyncio
async def test_authorize_missing_pkce_rejected(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    params = authorize_params(app_data["client_id"])
    del params["code_challenge"]
    resp = await async_client.get("/api/v1/oauth/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_authorize_plain_code_challenge_method_rejected(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], challenge_method="plain", code_challenge="short"),
        follow_redirects=False,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_load_transaction_returns_safe_context(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "branding": {
                "logo_url": "https://cdn.example.com/logo.png",
                "primary_color": "#112233",
            },
        },
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.get(f"/api/v1/auth-sessions/{tx_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == tx_id
    assert data["status"] == "pending"
    assert data["scopes"] == ["openid", "profile", "email"]
    app = data["application"]
    assert app["name"] == app_data["name"]
    assert app["logo_url"] == "https://cdn.example.com/logo.png"
    assert app["primary_color"] == "#112233"
    assert app["allow_signup"] is True

    body = resp.text
    for secret in ("client_secret", "code_challenge", "state", "hashed_secret", "nonce"):
        assert secret not in body


@pytest.mark.asyncio
async def test_load_transaction_unknown_transaction(async_client: AsyncClient):
    resp = await async_client.get("/api/v1/auth-sessions/tx_nonexistent")
    assert resp.status_code == 404
    assert resp.json()["error"] == "invalid_session"


@pytest.mark.asyncio
async def test_expired_transaction_reported_and_unusable(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    await _expire_transaction(db, tx_id)

    # Load reports expired
    resp = await async_client.get(f"/api/v1/auth-sessions/{tx_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "expired"

    # Login must fail with transaction_expired
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": "a@example.com", "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_expired"


@pytest.mark.asyncio
async def test_completed_transaction_reuse_rejected(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_id, email, "password123")

    # Exchange succeeds once
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app_data["client_id"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert resp.status_code == 200

    # Login on a completed transaction must be rejected
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_completed"


@pytest.mark.asyncio
async def test_cancelled_transaction_reuse_rejected(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.post(f"/api/v1/auth-sessions/{tx_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": "a@example.com", "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_cancelled"


@pytest.mark.asyncio
async def test_transaction_application_binding(async_client: AsyncClient, db):
    """
    A transaction belongs to exactly one application; a transaction from app A
    must never work against app B.
    """
    app_a = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    app_b = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])

    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["application_id"] == app_a["id"]

    # A login attempt with app B's client_id cannot affect the transaction
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": f"user-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
        headers={"x-application-id": app_b["client_id"]},
    )
    # Login errors are credential failures; the transaction is still bound to app A
    assert resp.status_code in (400, 401)
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["application_id"] == app_a["id"]
    assert doc["client_id"] == app_a["client_id"]


@pytest.mark.asyncio
async def test_authorize_preserves_state_and_nonce_in_transaction(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(
        async_client, app_data["client_id"], state="client-state-42", nonce="nonce-7"
    )
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["state"] == "client-state-42"
    assert doc["nonce"] == "nonce-7"


@pytest.mark.asyncio
async def test_internal_transaction_creation_admin_protected(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    params = authorize_params(app_data["client_id"])
    resp = await async_client.post("/api/v1/admin/auth-sessions", json=params)
    assert resp.status_code in (403, 422)

    resp = await async_client.post("/api/v1/admin/auth-sessions",
        json=params,
        headers={"x-admin-token": settings.admin_secret},
    )
    assert resp.status_code == 200
    assert resp.json()["session_id"].startswith("tx_")
    assert resp.json()["status"] == "pending"
