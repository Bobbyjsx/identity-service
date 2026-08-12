from fastapi import APIRouter

from app.services.key_manager import key_manager

router = APIRouter()

@router.get("/.well-known/jwks.json")
async def get_jwks():
    """
    Standard JWKS endpoint exposing active public keys for
    downstream microservices to verify JWT signatures statelessly.
    """
    return await key_manager.get_jwks()
