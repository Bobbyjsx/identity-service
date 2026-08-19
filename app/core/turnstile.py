import httpx
from fastapi import HTTPException, Request, status

from app.core.config import settings

TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def extract_client_ip(request: Request) -> str | None:
    """
    Extracts the client IP from the request, preferring Cloudflare's
    CF-Connecting-IP header, then the first X-Forwarded-For hop, before
    falling back to the direct connection peer.
    """
    cf_connecting = request.headers.get("CF-Connecting-IP")
    if cf_connecting:
        return cf_connecting.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        first_hop = forwarded.split(",")[0].strip()
        if first_hop:
            return first_hop
    return request.client.host if request.client else None


async def verify_turnstile_token(
    token: str | None,
    expected_action: str | tuple[str, ...],
    client_ip: str | None = None,
) -> None:
    """
    Validates Cloudflare Turnstile token server-side.

    `expected_action` accepts a single action or a tuple of acceptable
    actions (used when one widget serves several endpoints, e.g. a shared
    OTP page for both verification and resend).
    """
    if not settings.turnstile_enabled:
        return

    if not token or len(token) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or missing Turnstile security token.",
        )

    expected_hostnames = {h.strip() for h in settings.turnstile_hostnames.split(",") if h.strip()}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                TURNSTILE_SITEVERIFY_URL,
                data={
                    "secret": settings.turnstile_secret_key,
                    "response": token,
                    "remoteip": client_ip or "",
                },
            )
            result = response.json()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Turnstile verification service unreachable.",
            ) from exc

    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security verification failed.",
        )

    expected_actions = (expected_action,) if isinstance(expected_action, str) else expected_action

    if result.get("action") not in expected_actions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security verification action mismatch.",
        )

    if expected_hostnames and result.get("hostname") not in expected_hostnames:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security verification hostname mismatch.",
        )
