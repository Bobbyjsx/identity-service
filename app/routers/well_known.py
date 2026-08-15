from fastapi import APIRouter

from app.core.config import settings
from app.schemas.application import KNOWN_GRANT_TYPES, KNOWN_OAUTH_SCOPES
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
    OpenID Connect discovery document. Only advertises what this service
    actually implements.
    """
    base = settings.public_base_url.rstrip("/")
    return {
        "issuer": settings.identity_issuer,
        "authorization_endpoint": f"{base}/api/v1/oauth/authorize",
        "token_endpoint": f"{base}/api/v1/oauth/token",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": sorted(KNOWN_GRANT_TYPES),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": sorted(KNOWN_OAUTH_SCOPES),
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "iat",
            "exp",
            "jti",
            "nonce",
            "email",
            "email_verified",
            "name",
            "preferred_username",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }
