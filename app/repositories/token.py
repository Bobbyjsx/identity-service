from typing import Any

from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from app.repositories.base import BaseRepository


class OpaqueTokenRepository(BaseRepository):
    """
    Generic repository for short-lived opaque tokens (password reset,
    email verification) that are looked up by their SHA-256 hash and
    marked used exactly once.
    """

    def __init__(self, db: AsyncClient, collection_name: str):
        super().__init__(db, collection_name)

    async def get_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        """
        Retrieves a token document by the hash of the raw token.
        """
        docs = (
            self.collection.where(filter=FieldFilter("token_hash", "==", token_hash))
            .limit(1)
            .stream()
        )
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                return data
        return None

    async def mark_used(self, token_id: str, used_at: str):
        """
        Marks a token as used.
        """
        await self.collection.document(token_id).update(
            {"status": "used", "used_at": used_at}
        )
