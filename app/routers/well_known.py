from fastapi import APIRouter

from app.core.config import settings
from app.services.key_manager import key_manager

router = APIRouter()

@router.get("/.well-known/jwks.json")
async def get_jwks():
    """
    Standard JWKS endpoint exposing active public keys for
    downstream microservices to verify JWT signatures statelessly.
    """
    return await key_manager.get_jwks()


@router.get("/.well-known/openid-configuration")
async def get_openid_configuration():
    """
    Minimal OpenID Connect discovery document for the hosted
    authorization flow.
    """
    base = settings.public_base_url.rstrip("/")
    return {
        "issuer": settings.oidc_issuer,
        "authorization_endpoint": f"{base}/api/v1/oauth/authorize",
        "token_endpoint": f"{base}/api/v1/oauth/token",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "code_challenge_methods_supported": ["S256"],
    }
