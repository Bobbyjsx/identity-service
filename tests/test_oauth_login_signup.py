import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from tests.conftest import (
    REDIRECT_URI,
    authorize_and_get_transaction,
    create_application,
)


@pytest.mark.asyncio
async def test_transaction_login_success(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "redirect_url" in data
    assert data["email_verification_required"] is False

    parsed = urlparse(data["redirect_url"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "app.example.com"
    assert parsed.path == "/callback"
    query = parse_qs(parsed.query)
    assert "code" in query
    assert query["code"][0].startswith("code_")
    assert query["state"][0] == "abc123"
    # No tokens may ever appear in the callback URL
    assert "access_token" not in parsed.query
    assert "refresh_token" not in parsed.query
    assert "id_token" not in parsed.query

    # Transaction is completed and associated with the user
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["status"] == "completed"
    assert doc["user_id"]
    assert doc["completed_at"]

    # Raw code is never persisted; only its hash
    docs = db.collection("authorization_codes").stream()
    stored = [d async for d in docs]
    raw_body = str(stored)
    assert query["code"][0] not in raw_body


@pytest.mark.asyncio
async def test_transaction_login_invalid_password(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_transaction_login_unknown_user(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": "nobody@example.com", "password": "password123"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_transaction_login_unknown_transaction(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/v1/auth-sessions/tx_nonexistent/login",
        json={"email": "a@example.com", "password": "password123"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"] == "invalid_session"


@pytest.mark.asyncio
async def test_transaction_login_wrong_application(async_client: AsyncClient):
    """
    A user belonging to app B cannot authenticate through a transaction
    created for app A.
    """
    app_a = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    app_b = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_b["client_id"]},
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_transaction_login_disabled_for_application(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "authentication": {"allow_password_login": False},
        },
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": "a@example.com", "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "password_login_disabled"


@pytest.mark.asyncio
async def test_transaction_signup_success(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"newuser-{uuid.uuid4().hex[:8]}@example.com"
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": email, "password": "password123", "username": "alice"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["redirect_url"]
    query = parse_qs(urlparse(data["redirect_url"]).query)
    assert "code" in query

    # User persisted within the transaction's application only
    users = [
        d async for d in db.collection("users").where("app_id", "==", app_data["client_id"]).stream()
    ]
    assert any(u.to_dict()["email"] == email for u in users)


@pytest.mark.asyncio
async def test_transaction_signup_disabled(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "authentication": {"allow_signup": False},
        },
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": f"x-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "signup_disabled"


@pytest.mark.asyncio
async def test_transaction_signup_duplicate_account(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "user_already_exists"


@pytest.mark.asyncio
async def test_transaction_signup_expired_transaction(async_client: AsyncClient, db):

    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    await db.collection("auth_sessions").document(tx_id).update(
        {"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": f"e-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_expired"


@pytest.mark.asyncio
async def test_generic_signup_respects_application_signup_policy(async_client: AsyncClient):
    """
    Disabling signup for an application must also block the direct /auth/signup
    endpoint - application restrictions cannot be bypassed through the generic API.
    """
    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "authentication": {"allow_signup": False},
        },
    )
    resp = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": f"x-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Signup is disabled for this application"


@pytest.mark.asyncio
async def test_email_verification_required_blocks_code_issuance(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "authentication": {"require_email_verification": True},
        },
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    # Signup requires verification: no authorization code may be issued
    email = f"v-{uuid.uuid4().hex[:8]}@example.com"
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["redirect_url"] is None
    assert data["email_verification_required"] is True

    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["status"] == "authenticated"
    assert doc["user_id"]

    codes = [
        d
        async for d in db.collection("authorization_codes")
        .where("session_id", "==", tx_id)
        .stream()
    ]
    assert len(codes) == 0

    # Login also cannot proceed without verification
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "email_verification_required"


@pytest.mark.asyncio
async def test_email_verification_completes_flow(async_client: AsyncClient, db, monkeypatch):
    """
    The verification token is delivered out-of-band via the notification
    boundary. This test emulates the provider receiving the raw token by
    monkeypatching the generator.
    """
    from app.services import oauth as oauth_module

    sent = {}

    def generator() -> str:
        sent["raw"] = f"ev_test_{uuid.uuid4().hex}"
        return sent["raw"]

    monkeypatch.setattr(oauth_module, "generate_verification_token", generator)

    app_data = await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "authentication": {"require_email_verification": True},
        },
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    email = f"v-{uuid.uuid4().hex[:8]}@example.com"
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": email, "password": "password123"},
    )
    assert resp.json()["email_verification_required"] is True
    raw_token = sent["raw"]
    assert raw_token

    # Raw token never persisted - only its hash
    docs = [d async for d in db.collection("email_verification_tokens").stream()]
    assert raw_token not in str(docs)

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/verify-email",
        json={"verification_token": raw_token},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["redirect_url"]
    assert parse_qs(urlparse(data["redirect_url"]).query)["code"][0].startswith("code_")

    # User is now verified
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    user = (await db.collection("users").document(doc["user_id"]).get()).to_dict()
    assert user["email_verified"] is True

    # Transaction completed
    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["status"] == "completed"


@pytest.mark.asyncio
async def test_callback_url_preserves_client_state(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(
        async_client, app_data["client_id"], state="custom-state-value"
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    query = parse_qs(urlparse(resp.json()["redirect_url"]).query)
    assert query["state"][0] == "custom-state-value"
