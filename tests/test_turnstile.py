from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.config import settings
from app.core.turnstile import extract_client_ip, verify_turnstile_token

TOKEN = "0xvalid-turnstile-token"


def _fake_async_client(payload: dict, *, error: Exception | None = None) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    if error is not None:
        client.post.side_effect = error
    else:
        client.post.return_value = MagicMock(json=MagicMock(return_value=payload))
    return client


def _valid_payload(**overrides) -> dict:
    payload = {
        "success": True,
        "action": "login",
        "hostname": "localhost",
    }
    payload.update(overrides)
    return payload


async def _call_with(
    monkeypatch, token, payload: dict, *, expected_action: str | tuple[str, ...] = "login", error=None
):
    monkeypatch.setattr(settings, "turnstile_enabled", True)
    monkeypatch.setattr(settings, "turnstile_hostnames", "localhost,127.0.0.1")
    client = _fake_async_client(payload, error=error)
    with patch("app.core.turnstile.httpx.AsyncClient", return_value=client) as mock_cls:
        await verify_turnstile_token(token, expected_action=expected_action, client_ip="127.0.0.1")
    mock_cls.assert_called_once_with(timeout=10.0)
    return client


@pytest.mark.asyncio
async def test_disabled_skips_verification(monkeypatch):
    monkeypatch.setattr(settings, "turnstile_enabled", False)
    with patch("app.core.turnstile.httpx.AsyncClient") as mock_cls:
        await verify_turnstile_token(None, expected_action="login")
    mock_cls.assert_not_called()


@pytest.mark.asyncio
async def test_missing_token_rejected(monkeypatch):
    monkeypatch.setattr(settings, "turnstile_enabled", True)
    with pytest.raises(HTTPException) as exc_info:
        await verify_turnstile_token(None, expected_action="login")
    assert exc_info.value.status_code == 400
    assert "Turnstile security token" in exc_info.value.detail


@pytest.mark.asyncio
async def test_token_too_long_rejected(monkeypatch):
    monkeypatch.setattr(settings, "turnstile_enabled", True)
    with pytest.raises(HTTPException) as exc_info:
        await verify_turnstile_token("x" * 2049, expected_action="login")
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_siteverify_unreachable_returns_502(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        await _call_with(
            monkeypatch,
            TOKEN,
            {},
            error=httpx.ConnectError("network down"),
        )
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_success_false_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        await _call_with(monkeypatch, TOKEN, {"success": False})
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Security verification failed."


@pytest.mark.asyncio
async def test_action_mismatch_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        await _call_with(monkeypatch, TOKEN, _valid_payload(action="signup"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Security verification action mismatch."


@pytest.mark.asyncio
async def test_multiple_actions_accepted(monkeypatch):
    for token_action in ("verify-email", "resend-otp"):
        await _call_with(
            monkeypatch,
            TOKEN,
            _valid_payload(action=token_action),
            expected_action=("verify-email", "resend-otp"),
        )


@pytest.mark.asyncio
async def test_multiple_actions_rejects_other_action(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        await _call_with(
            monkeypatch,
            TOKEN,
            _valid_payload(action="login"),
            expected_action=("verify-email", "resend-otp"),
        )
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Security verification action mismatch."


@pytest.mark.asyncio
async def test_hostname_mismatch_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        await _call_with(monkeypatch, TOKEN, _valid_payload(hostname="attacker.example.com"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Security verification hostname mismatch."


@pytest.mark.asyncio
async def test_valid_token_passes(monkeypatch):
    client = await _call_with(monkeypatch, TOKEN, _valid_payload())
    post_kwargs = client.post.call_args.kwargs
    assert post_kwargs["data"]["response"] == TOKEN
    assert post_kwargs["data"]["remoteip"] == "127.0.0.1"


def test_extract_client_ip_prefers_cf_connecting_ip():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"cf-connecting-ip", b"198.51.100.7"),
                (b"x-forwarded-for", b"203.0.113.9, 10.0.0.1"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )
    assert extract_client_ip(request) == "198.51.100.7"


def test_extract_client_ip_prefers_x_forwarded_for():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"203.0.113.9, 10.0.0.1")],
            "client": ("127.0.0.1", 1234),
        }
    )
    assert extract_client_ip(request) == "203.0.113.9"


def test_extract_client_ip_falls_back_to_peer():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [],
            "client": ("127.0.0.1", 1234),
        }
    )
    assert extract_client_ip(request) == "127.0.0.1"


def test_extract_client_ip_returns_none_without_client():
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    assert extract_client_ip(request) is None
