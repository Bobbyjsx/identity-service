import uuid
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.core.security import hash_token
from tests.conftest import (
    REDIRECT_URI,
    authorize_and_get_transaction,
    create_application,
    login_and_get_code,
    pkce_pair,
)


@pytest.mark.asyncio
async def test_cross_application_transaction_isolation(async_client: AsyncClient):
    """
    Application A cannot use an authorization transaction created for
    application B, and vice versa.
    """
    app_a = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    app_b = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_a, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_b["client_id"]},
    )

    # App B's user cannot authenticate through app A's transaction
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_a}/login",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"

    # A signup through app A's transaction creates an isolated user in app A
    # only; it does not collide with (or affect) the app B account.
    tx_a2, _, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])
    resp = await async_client.post(
        f"/api/v1/auth-sessions/{tx_a2}/signup",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 200
    assert resp.json()["redirect_url"]


@pytest.mark.asyncio
async def test_cross_application_code_redemption_impossible(async_client: AsyncClient):
    """
    A code issued for app A can never be redeemed by app B because the code
    is bound to the client_id, application, transaction, and user.
    """
    app_a = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    app_b = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_a, verifier, _ = await authorize_and_get_transaction(async_client, app_a["client_id"])
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_a["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_a, email, "password123")

    # App B presents app A's code with app B's client_id
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app_b["client_id"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_cross_application_configuration_isolation(async_client: AsyncClient):
    await create_application(
        async_client,
        config={
            "oauth": {"redirect_uris": [REDIRECT_URI]},
            "branding": {"primary_color": "#111111"},
        },
    )
    app_b = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    config_b = (await async_client.get(f"/api/v1/applications/{app_b['client_id']}/configuration")).json()
    assert config_b["primary_color"] is None
    assert config_b["primary_color"] != "#111111"


@pytest.mark.asyncio
async def test_redirect_uri_manipulation_at_exchange(async_client: AsyncClient):
    """
    The redirect URI used at the token endpoint must exactly match the one
    registered and used during the authorization request.
    """
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_id, email, "password123")

    for tampered in (
        f"{REDIRECT_URI}/suffix",
        REDIRECT_URI.replace("https", "http"),
        "https://app.example.com/other",
        f"{REDIRECT_URI}?x=1",
    ):
        resp = await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": app_data["client_id"],
                "redirect_uri": tampered,
                "code_verifier": verifier,
            },
        )
        assert resp.status_code == 400, f"{tampered} should be rejected"
        assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_authorize_rejects_unregistered_domain(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params={
            "client_id": app_data["client_id"],
            "redirect_uri": "https://attacker.example.com/cb",
            "response_type": "code",
            "code_challenge": pkce_pair()[1],
            "code_challenge_method": "S256",
            "state": "x",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_authorize_rejects_javascript_uri(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    resp = await async_client.get(
        "/api/v1/oauth/authorize",
        params={
            "client_id": app_data["client_id"],
            "redirect_uri": "javascript:alert(1)",
            "response_type": "code",
            "code_challenge": pkce_pair()[1],
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_transaction_id_is_opaque_and_high_entropy(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    seen = set()
    for _ in range(5):
        tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
        assert tx_id.startswith("tx_")
        assert len(tx_id) > 30
        seen.add(tx_id)
    assert len(seen) == 5


@pytest.mark.asyncio
async def test_id_token_audience_is_client(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_id, email, "password123")
    data = (
        await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": app_data["client_id"],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            },
        )
    ).json()

    id_token = jwt.decode(data["id_token"], options={"verify_signature": False})
    assert id_token["aud"] == app_data["client_id"]
    assert id_token["aud"] != "application_api"  # distinct from the access token audience
    assert "hashed_secret" not in id_token
    assert "client_secret" not in id_token
    assert "private_key" not in id_token


@pytest.mark.asyncio
async def test_id_token_signature_verifies_with_jwks(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, verifier, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_id, email, "password123")
    data = (
        await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": app_data["client_id"],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            },
        )
    ).json()

    jwks = (await async_client.get("/.well-known/jwks.json")).json()
    jwk = jwks["keys"][0]
    kid = jwt.get_unverified_header(data["id_token"])["kid"]
    assert kid == jwk["kid"]

    key = jwt.algorithms.get_default_algorithms()["EdDSA"].from_jwk(jwk)
    payload = jwt.decode(
        data["id_token"],
        key,
        algorithms=["EdDSA"],
        audience=app_data["client_id"],
        issuer=settings.identity_issuer,
    )
    assert payload["sub"]


@pytest.mark.asyncio
async def test_jwks_endpoint_unchanged(async_client: AsyncClient):
    resp = await async_client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert len(keys) >= 1
    assert keys[0]["kty"] == "OKP"
    assert keys[0]["crv"] == "Ed25519"


@pytest.mark.asyncio
async def test_oidc_discovery_document(async_client: AsyncClient):
    resp = await async_client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["issuer"] == settings.identity_issuer
    assert doc["authorization_endpoint"] == f"{settings.public_base_url}/api/v1/oauth/authorize"
    assert doc["token_endpoint"] == f"{settings.public_base_url}/api/v1/oauth/token"
    assert doc["response_types_supported"] == ["code"]
    assert "authorization_code" in doc["grant_types_supported"]
    assert "client_credentials" in doc["grant_types_supported"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert "offline_access" not in doc["scopes_supported"]
    assert set(doc["scopes_supported"]) == {"openid", "profile", "email"}
    assert "iss" in doc["claims_supported"]
    assert "nonce" in doc["claims_supported"]
    assert "token" not in doc["response_types_supported"]
    assert "plain" not in doc["code_challenge_methods_supported"]


@pytest.mark.asyncio
async def test_invalid_signature_rejected_by_api(async_client: AsyncClient):
    """
    Tokens signed with the wrong key (invalid signature) must be rejected
    by the existing JWT verification path.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    other_key = ed25519.Ed25519PrivateKey.generate()
    bogus = jwt.encode(
        {
            "iss": settings.identity_issuer,
            "sub": "user_x",
            "aud": "application_api",
            "app_id": "app_x",
            "type": "user",
        },
        other_key,
        algorithm="EdDSA",
    )
    resp = await async_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bogus}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_incorrect_audience_rejected(async_client: AsyncClient):
    app_data = await create_application(
        async_client,
        config={"oauth": {"allowed_grants": ["authorization_code", "client_credentials"]}},
    )
    resp = await async_client.post(
        "/api/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": app_data["client_id"],
            "client_secret": app_data["client_secret"],
            "audience": "file_service_a",
        },
    )
    token = resp.json()["access_token"]
    # A resource server for a different audience must not accept it
    from app.services.key_manager import key_manager

    with pytest.raises(jwt.InvalidAudienceError):
        key_manager.verify_jwt(token, audience=["file_service_b"])

    # The intended audience verifies fine
    verified = key_manager.verify_jwt(token, audience=["file_service_a"])
    assert verified["type"] == "service"


@pytest.mark.asyncio
async def test_error_responses_do_not_leak_stack_traces(async_client: AsyncClient):
    resp = await async_client.get("/api/v1/auth-sessions/tx_nonexistent")
    body = resp.text
    assert "Traceback" not in body
    assert 'File "' not in body
    assert resp.json()["error"] == "invalid_session"


@pytest.mark.asyncio
async def test_raw_authorization_code_never_persisted(async_client: AsyncClient, db):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    await async_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "password123"},
        headers={"x-application-id": app_data["client_id"]},
    )
    code = await login_and_get_code(async_client, tx_id, email, "password123")

    docs = [
        d.to_dict() async for d in db.collection("authorization_codes").where("session_id", "==", tx_id).stream()
    ]
    assert len(docs) == 1
    stored = docs[0]
    assert stored["code_hash"] == hash_token(code)
    assert code not in stored.values()


@pytest.mark.asyncio
async def test_transaction_secrets_not_exposed_in_documents(async_client: AsyncClient, db):
    """
    The hosted UI must not be able to extract client secrets or challenges
    from transaction-related responses.
    """
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
    tx_id, _, _ = await authorize_and_get_transaction(async_client, app_data["client_id"])

    resp = await async_client.get(f"/api/v1/auth-sessions/{tx_id}")
    body = resp.text
    for secret in ("code_challenge", "client_secret", "nonce", "state", "hashed_secret"):
        assert secret not in body

    config_resp = await async_client.get(f"/api/v1/applications/{app_data['client_id']}/configuration")
    body = config_resp.text
    for secret in ("client_secret", "hashed_secret", "redirect_uris"):
        assert secret not in body


@pytest.mark.asyncio
async def test_callback_redirect_contains_only_code_and_state(async_client: AsyncClient):
    app_data = await create_application(async_client, config={"oauth": {"redirect_uris": [REDIRECT_URI]}})
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
    redirect_url = resp.json()["redirect_url"]
    parsed = urlparse(redirect_url)
    assert set(parse_qs(parsed.query).keys()) == {"code", "state"}
    for forbidden in ("access_token", "refresh_token", "id_token", "client_secret", "tx_"):
        assert forbidden not in redirect_url
