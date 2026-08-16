import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import (
    CLIENT_CREDENTIALS_OAUTH,
    REDIRECT_URI,
    authorize_and_get_transaction,
    authorize_params,
    create_application,
    login_and_get_code,
)


async def _signup(async_client: AsyncClient, client_id: str, email: str | None = None) -> str:
    email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
    resp = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": client_id},
    )
    assert resp.status_code == 200, resp.text
    return email


@pytest.mark.asyncio
async def test_concurrent_login_issues_single_authorization_code(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])

    async def login():
        return await async_client.post(
            f"/api/v1/auth-sessions/{tx_id}/login",
            json={"email": email, "password": "password123"},
        )

    first, second = await asyncio.gather(login(), login())
    results = [first, second]
    successes = [r for r in results if r.status_code == 200 and r.json().get("redirect_url")]
    failures = [r for r in results if r.status_code != 200 or not r.json().get("redirect_url")]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].json()["error"] in {
        "invalid_transaction_state",
        "session_completed",
        "email_verification_required",
    }

    codes = [d async for d in db.collection("authorization_codes").where("session_id", "==", tx_id).stream()]
    assert len(codes) == 1

    doc = (await db.collection("auth_sessions").document(tx_id).get()).to_dict()
    assert doc["status"] == "completed"


@pytest.mark.asyncio
async def test_redemption_database_failure_is_server_error(async_client: AsyncClient, monkeypatch):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])
    code = await login_and_get_code(async_client, tx_id, email, "password123")

    async def boom(*_args, **_kwargs):
        raise RuntimeError("Firestore unavailable: projects/test/databases/(default)")

    monkeypatch.setattr(
        "app.repositories.authorization_code.AuthorizationCodeRepository.mark_used_atomic",
        boom,
    )

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
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "server_error"
    assert "Firestore" not in resp.text
    assert "projects/" not in resp.text
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_default_application_cannot_use_client_credentials(async_client: AsyncClient):
    app_data = await create_application(async_client)
    assert app_data.get("oauth", {}).get("allowed_grants", ["authorization_code"]) == ["authorization_code"]

    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": app_data["client_id"],
            "client_secret": app_data["client_secret"],
            "audience": "orders-api",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unauthorized_client"

    legacy = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": app_data["client_id"],
            "client_secret": app_data["client_secret"],
            "audience": "orders-api",
        },
    )
    assert legacy.status_code == 400
    assert legacy.json()["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_opt_in_client_credentials_succeeds(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": CLIENT_CREDENTIALS_OAUTH})
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": app_data["client_id"],
            "client_secret": app_data["client_secret"],
            "audience": "orders-api",
        },
    )
    assert resp.status_code == 200, resp.text
    token = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    assert token["type"] == "service"
    assert token["iss"] == settings.identity_issuer
    assert token["aud"] == "orders-api"


@pytest.mark.asyncio
async def test_public_client_exchanges_code_without_secret(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        client_type="public",
        config={"oauth": {"redirect_uris": [REDIRECT_URI]}},
    )
    assert app_data["client_type"] == "public"
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])
    code = await login_and_get_code(async_client, tx_id, email, "password123")

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
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_confidential_client_requires_secret_and_pkce(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        client_type="confidential",
        config={"oauth": {"redirect_uris": [REDIRECT_URI]}},
    )
    assert app_data["client_type"] == "confidential"
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])
    code = await login_and_get_code(async_client, tx_id, email, "password123")

    missing = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app_data["client_id"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert missing.status_code == 401
    assert missing.json()["error"] == "invalid_client"

    ok = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app_data["client_id"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_secret": app_data["client_secret"],
        },
    )
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_offline_access_is_not_a_supported_scope(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params=authorize_params(app_data["client_id"], scope="openid offline_access"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert parse_qs(urlparse(resp.headers["location"]).query)["error"][0] == "invalid_scope"


@pytest.mark.asyncio
async def test_existing_application_missing_fields_gets_safe_defaults(async_client: AsyncClient, db):
    app_data = await create_application(async_client)
    await (
        db.collection("applications")
        .document(app_data["id"])
        .update({"branding": None, "authentication": None, "oauth": None, "client_type": None})
    )
    resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
    assert resp.status_code == 200
    config = resp.json()
    assert config["allow_signup"] is True
    assert config["allowed_scopes"] == ["openid", "profile", "email"]
    assert "client_secret" not in config
    assert "redirect_uris" not in config
    assert "client_type" not in config


@pytest.mark.asyncio
async def test_cancelled_transaction_cannot_be_completed(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])
    await async_client.post(f"/api/v1/auth-sessions/{tx_id}/cancel")

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_cancelled"

    cancel_again = await async_client.post(f"/api/v1/auth-sessions/{tx_id}/cancel")
    assert cancel_again.status_code == 400
    assert cancel_again.json()["error"] == "session_cancelled"


@pytest.mark.asyncio
async def test_completed_transaction_cannot_be_cancelled(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = await _signup(async_client, app_data["client_id"])
    await login_and_get_code(async_client, tx_id, email, "password123")

    resp = await async_client.post(f"/api/v1/auth-sessions/{tx_id}/cancel")
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_completed"


@pytest.mark.asyncio
async def test_authenticated_transaction_expires(async_client: AsyncClient, db, monkeypatch):
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
    await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/signup",
        json={"email": f"v-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
    )
    await (
        db.collection("auth_sessions")
        .document(tx_id)
        .update({"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()})
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_id}/verify-email",
        json={"verification_token": sent["raw"]},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "session_expired"


@pytest.mark.asyncio
async def test_verification_token_cannot_cross_applications(async_client: AsyncClient, db, monkeypatch):
    from app.services import oauth as oauth_module

    tokens: list[str] = []

    def generator() -> str:
        raw = f"ev_test_{uuid.uuid4().hex}"
        tokens.append(raw)
        return raw

    monkeypatch.setattr(oauth_module, "generate_verification_token", generator)

    config = {
        "oauth": {"redirect_uris": [REDIRECT_URI]},
        "authentication": {"require_email_verification": True},
    }
    app_a = await create_application(async_client, config=config)
    app_b = await create_application(async_client, config=config)

    tx_a, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])
    await async_client.post(
        f"/api/v1/auth-sessions/{tx_a}/signup",
        json={"email": f"a-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
    )
    token_a = tokens[-1]

    tx_b, _, _ = await authorize_and_get_transaction(async_client, app_b["client_id"])
    await async_client.post(
        f"/api/v1/auth-sessions/{tx_b}/signup",
        json={"email": f"b-{uuid.uuid4().hex[:8]}@example.com", "password": "password123"},
    )

    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_b}/verify-email",
        json={"verification_token": token_a},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_verification_token"

    doc_b = (await db.collection("auth_sessions").document(tx_b).get()).to_dict()
    assert doc_b["status"] == "authenticated"
    codes_b = [d async for d in db.collection("authorization_codes").where("session_id", "==", tx_b).stream()]
    assert codes_b == []


@pytest.mark.asyncio
async def test_application_create_accepts_full_configuration(async_client: AsyncClient):
    from app.core.config import settings as app_settings

    resp = await async_client.post("/api/v1/admin/applications",
        json={
            "name": "Provisioned",
            "description": "created atomically",
            "client_type": "confidential",
            "oauth": {
                "redirect_uris": [REDIRECT_URI],
                "allowed_grants": ["authorization_code", "client_credentials"],
            },
            "authentication": {"allow_signup": False},
        },
        headers={"x-admin-token": app_settings.admin_secret},
    )
    assert resp.status_code == 200, resp.text
    client_id = resp.json()["client_id"]

    detail = await async_client.get(
        f"/api/v1/admin/applications/{client_id}",
        headers={"x-admin-token": app_settings.admin_secret},
    )
    body = detail.json()
    assert body["client_type"] == "confidential"
    assert body["authentication"]["allow_signup"] is False
    assert REDIRECT_URI in body["oauth"]["redirect_uris"]
    assert "client_credentials" in body["oauth"]["allowed_grants"]


@pytest.mark.asyncio
async def test_public_configuration_hides_internal_fields(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        client_type="confidential",
        config={"oauth": {"redirect_uris": [REDIRECT_URI]}},
    )
    resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
    body = resp.json()
    for hidden in (
        "client_secret",
        "hashed_secret",
        "redirect_uris",
        "client_type",
        "allowed_grants",
        "id",
        "status",
    ):
        assert hidden not in body
