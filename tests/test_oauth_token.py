import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import (
    REDIRECT_URI,
    authorize_and_get_transaction,
    create_application,
    login_and_get_code,
    pkce_pair,
)


async def _signup_user(async_client: AsyncClient, client_id: str) -> str:
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    resp = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": client_id},
    )
    assert resp.status_code == 200
    return email


async def _full_flow(
    async_client: AsyncClient, app_data: dict, scope: str = "openid profile email", nonce: str = "abc123"
):
    """
    Runs authorize -> login -> code, returns (code, verifier, email).
    """
    tx_id, verifier, _ = await authorize_and_get_transaction(
        async_client, app_data["client_id"], scope=scope, nonce=nonce
    )
    email = await _signup_user(async_client, app_data["client_id"])
    code = await login_and_get_code(async_client, tx_id, email, "password123")
    return code, verifier, email


async def _exchange(
    async_client: AsyncClient,
    *,
    code: str,
    verifier: str,
    client_id: str,
    redirect_uri: str = REDIRECT_URI,
    **overrides,
):
    return await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            **overrides,
        },
    )


@pytest.mark.asyncio
async def test_valid_authorization_code_exchange(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    resp = await _exchange(
        async_client, code=code, verifier=verifier, client_id=app_data["client_id"]
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == settings.jwt_expiration_minutes * 60
    assert "id_token" in data  # openid scope requested

    access = jwt.decode(data["access_token"], options={"verify_signature": False})
    assert access["iss"] == settings.jwt_issuer
    assert access["type"] == "user"
    assert access["aud"] == "application_api"
    assert access["app_id"] == app_data["client_id"]
    assert access["scope"] == "openid profile email"
    assert access["roles"] == []

    id_token = jwt.decode(data["id_token"], options={"verify_signature": False})
    assert id_token["iss"] == settings.oidc_issuer
    assert id_token["aud"] == app_data["client_id"]
    assert id_token["sub"] == access["sub"]
    assert id_token["exp"] > id_token["iat"]
    assert "email" in id_token
    assert "email_verified" in id_token
    assert id_token["nonce"] == "abc123"


@pytest.mark.asyncio
async def test_access_token_verifiable_and_useful(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)
    data = (await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])).json()

    # Access token works against the existing /auth/me endpoint
    resp = await async_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"}
    )
    assert resp.status_code == 200
    assert resp.json()["email"]


@pytest.mark.asyncio
async def test_refresh_token_from_exchange_works(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)
    data = (await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])).json()

    resp = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": data["refresh_token"]}
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert "access_token" in new_tokens
    assert new_tokens["refresh_token"] != data["refresh_token"]


@pytest.mark.asyncio
async def test_no_openid_scope_no_id_token(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data, scope="")
    data = (await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])).json()
    assert data.get("id_token") is None
    access = jwt.decode(data["access_token"], options={"verify_signature": False})
    assert "scope" not in access or access["scope"] == ""


@pytest.mark.asyncio
async def test_invalid_code_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    _, verifier, _ = await _full_flow(async_client, app_data)
    resp = await _exchange(
        async_client, code="code_fake", verifier=verifier, client_id=app_data["client_id"]
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_expired_code_rejected(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    from app.core.security import hash_token

    docs = db.collection("authorization_codes").where("code_hash", "==", hash_token(code)).stream()
    async for doc in docs:
        await db.collection("authorization_codes").document(doc.id).update(
            {"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}
        )

    resp = await _exchange(
        async_client, code=code, verifier=verifier, client_id=app_data["client_id"]
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_reused_code_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    first = await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])
    assert first.status_code == 200

    second = await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_wrong_client_rejected(async_client: AsyncClient):
    app_a = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    app_b = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_a)

    resp = await _exchange(async_client, code=code, verifier=verifier, client_id=app_b["client_id"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_wrong_redirect_uri_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    resp = await _exchange(
        async_client,
        code=code,
        verifier=verifier,
        client_id=app_data["client_id"],
        redirect_uri="https://evil.example.com/callback",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_wrong_pkce_verifier_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, _, _ = await _full_flow(async_client, app_data)
    wrong_verifier, _ = pkce_pair()

    resp = await _exchange(
        async_client, code=code, verifier=wrong_verifier, client_id=app_data["client_id"]
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_missing_pkce_verifier_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, _, _ = await _full_flow(async_client, app_data)

    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app_data["client_id"],
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_malformed_token_request(async_client: AsyncClient):
    resp = await async_client.post("/api/v1/oauth/token", data={"grant_type": "bogus"})
    # Missing required form fields are rejected by FastAPI validation
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_unsupported_grant_type(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "password",
            "client_id": "app_x",
            "username": "a",
            "password": "b",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_client_credentials_flow_still_works(async_client: AsyncClient):
    """
    The existing service-token flow must continue to work on the new token
    endpoint and the legacy endpoint.
    """
    app_data = await create_application(async_client)

    for endpoint in ("/api/v1/oauth/token", "/api/v1/auth/oauth/token"):
        resp = await async_client.post(
            endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": app_data["client_id"],
                "client_secret": app_data["client_secret"],
                "audience": "custom_file_service",
            },
        )
        assert resp.status_code == 200, resp.text
        token = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
        assert token["type"] == "service"
        assert token["aud"] == "custom_file_service"
        assert token["app_id"] == app_data["id"]


@pytest.mark.asyncio
async def test_client_credentials_bad_secret_still_rejected(async_client: AsyncClient):
    app_data = await create_application(async_client)
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": app_data["client_id"],
            "client_secret": "wrong",
            "audience": "svc",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_authorization_code_with_client_secret(async_client: AsyncClient):
    """
    Confidential-client style exchange: providing the correct client_secret
    must succeed; a wrong secret must be rejected.
    """
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    resp = await _exchange(
        async_client,
        code=code,
        verifier=verifier,
        client_id=app_data["client_id"],
        client_secret=app_data["client_secret"],
    )
    assert resp.status_code == 200

    code2, verifier2, _ = await _full_flow(async_client, app_data)
    resp = await _exchange(
        async_client,
        code=code2,
        verifier=verifier2,
        client_id=app_data["client_id"],
        client_secret="wrong-secret",
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_grant_disabled_for_application(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={
            "oauth": {
                "redirect_uris": [REDIRECT_URI],
                "allowed_grants": ["client_credentials"],
            }
        },
    )
    code, verifier, _ = await _full_flow(async_client, app_data)
    resp = await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_user_deleted_after_code_issued(async_client: AsyncClient, db):
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, email = await _full_flow(async_client, app_data)

    users = db.collection("users").where("app_id", "==", app_data["client_id"]).stream()
    async for u in users:
        if u.to_dict()["email"] == email:
            await db.collection("users").document(u.id).delete()

    resp = await _exchange(async_client, code=code, verifier=verifier, client_id=app_data["client_id"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_concurrent_redemption_single_use(async_client: AsyncClient):
    """
    Race condition test: two concurrent redemption attempts for the same code.
    Exactly one must succeed.
    """
    app_data = await create_application(
        async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}}
    )
    code, verifier, _ = await _full_flow(async_client, app_data)

    async def redeem():
        return await _exchange(
            async_client, code=code, verifier=verifier, client_id=app_data["client_id"]
        )

    results = await asyncio.gather(redeem(), redeem())
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 400]
    failed = results[[r.status_code for r in results].index(400)]
    assert failed.json()["error"] == "invalid_grant"
