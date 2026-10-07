import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from tests.conftest import (
    REDIRECT_URI,
    authorize_and_get_transaction,
    create_application,
)


async def _tokens_for(db, client_id: str) -> list:
    return [
        d
        async for d in db.collection("password_reset_tokens")
        .where("app_id", "==", client_id)
        .stream()
    ]


@pytest.fixture
def reset_token(monkeypatch):
    """
    Returns a function that runs forgot-password with a deterministic raw
    token, simulating what the notification provider would receive.
    """
    from app.services import oauth as oauth_module

    state = {"raw": None}

    def generator() -> str:
        state["raw"] = f"pr_test_{uuid.uuid4().hex}"
        return state["raw"]

    monkeypatch.setattr(oauth_module, "generate_password_reset_token", generator)

    async def _create(async_client: AsyncClient, db, app_data: dict, email: str):
        tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
        resp = await async_client.post(
            f"/api/v1/auth-sessions/{tx_id}/forgot-password", json={"email": email}
        )
        assert resp.status_code == 200
        return tx_id, state["raw"]

    return _create


@pytest.mark.asyncio
async def test_forgot_password_enumeration_safe(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    # Existing email
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    resp_existing = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/forgot-password", json={"email": email}
    )

    # Unknown email
    resp_unknown = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/forgot-password",
        json={"email": "nobody@example.com"},
    )

    # Identical responses - no account enumeration
    assert resp_existing.status_code == 200
    assert resp_unknown.status_code == 200
    assert resp_existing.json() == resp_unknown.json()
    assert "token" not in resp_existing.text
    assert "pr_" not in resp_existing.text


@pytest.mark.asyncio
async def test_forgot_password_creates_hashed_token_only(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    _, raw_token = await create_application_reset_token(async_client, db, app_data, email)

    tokens = [
        d
        async for d in db.collection("password_reset_tokens")
        .where("app_id", "==", app_data["client_id"])
        .stream()
    ]
    assert len(tokens) == 1
    doc = tokens[0].to_dict()
    assert doc["app_id"] == app_data["client_id"]
    assert doc["status"] == "active"
    assert "token_hash" in doc
    # Raw token never stored
    assert raw_token not in doc.values()
    assert doc["token_hash"] != raw_token


async def create_application_reset_token(async_client: AsyncClient, db, app_data: dict, email: str):
    """
    Runs forgot-password WITHOUT a deterministic token and returns the
    transaction id and the raw token from the notification stub.
    """
    from app.services import oauth as oauth_module

    sent = {}

    original = oauth_module.generate_password_reset_token

    def generator() -> str:
        sent["raw"] = original()
        return sent["raw"]

    oauth_module.generate_password_reset_token = generator
    try:
        tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
        resp = await async_client.post(
            f"/api/v1/auth-sessions/{tx_id}/forgot-password", json={"email": email}
        )
        assert resp.status_code == 200
        return tx_id, sent["raw"]
    finally:
        oauth_module.generate_password_reset_token = original


@pytest.mark.asyncio
async def test_reset_password_completes_transaction_flow(
    async_client: AsyncClient, db, reset_token
):
    """
    Full reset lifecycle: forgot-password creates a token, the user completes
    the reset through the transaction, then can log in with the new password.
    """
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    tx_id, raw_token = await reset_token(async_client, db, app_data, email)

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/reset-password",
        json={"reset_token": raw_token, "new_password": "newpassword456"},
    )
    assert resp.status_code == 200
    assert "Password has been reset" in resp.json()["detail"]

    # Token is now used
    tokens = await _tokens_for(db, app_data["client_id"])
    assert tokens[0].to_dict()["status"] == "used"

    # New password works
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "newpassword456"},
    )
    assert resp.status_code == 200
    assert resp.json()["redirect_url"]

    # Old password no longer works (on a fresh transaction)
    tx2, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx2}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_reset_password_standalone(async_client: AsyncClient, db, reset_token):
    """
    The email link can be opened outside an active transaction; the reset
    token carries its own application context.
    """
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    _, raw_token = await reset_token(async_client, db, app_data, email)

    resp = await async_client.post(
        "/api/v1/auth/password/reset",
        json={"reset_token": raw_token, "new_password": "standalone456"},
    )
    assert resp.status_code == 200

    # New password authenticates via the normal login path
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "standalone456"},
        headers={"x-application-id": app_data["client_id"]},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_reset_password_invalid_token(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/reset-password",
        json={"reset_token": "pr_bogus_token_123456", "new_password": "newpassword456"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_reset_token"


@pytest.mark.asyncio
async def test_reset_password_expired_token(async_client: AsyncClient, db, reset_token):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    tx_id, raw_token = await reset_token(async_client, db, app_data, email)

    tokens = await _tokens_for(db, app_data["client_id"])
    await db.collection("password_reset_tokens").document(tokens[0].id).update(
        {"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/reset-password",
        json={"reset_token": raw_token, "new_password": "newpassword456"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "reset_token_expired"


@pytest.mark.asyncio
async def test_reset_password_wrong_application_token(async_client: AsyncClient, db, reset_token):
    """
    A reset token minted for app B must not be usable through an app A
    transaction.
    """
    app_a = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    app_b = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_b["client_id"]},
    )
    _, raw_token = await reset_token(async_client, db, app_b, email)

    tx_a, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_a}/reset-password",
        json={"reset_token": raw_token, "new_password": "newpassword456"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_reset_token"


@pytest.mark.asyncio
async def test_reset_password_reused_token_rejected(async_client: AsyncClient, db, reset_token):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    tx_id, raw_token = await reset_token(async_client, db, app_data, email)

    first = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/reset-password",
        json={"reset_token": raw_token, "new_password": "newpassword456"},
    )
    assert first.status_code == 200

    tx_id2, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    second = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id2}/reset-password",
        json={"reset_token": raw_token, "new_password": "anotherpass789"},
    )
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_reset_token"


@pytest.mark.asyncio
async def test_reset_password_revokes_refresh_tokens(async_client: AsyncClient, db, reset_token):
    """
    After a password reset, previously issued refresh tokens must be unusable.
    """
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    old_refresh = login.json()["refresh_token"]

    tx_id, raw_token = await reset_token(async_client, db, app_data, email)
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/reset-password",
        json={"reset_token": raw_token, "new_password": "newpassword456"},
    )
    assert resp.status_code == 200

    resp = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": old_refresh}
    )
    assert resp.status_code == 401
