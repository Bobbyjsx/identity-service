from typing import Any

from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from app.repositories.base import BaseRepository


class RefreshTokenRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        """
        Initializes the RefreshTokenRepository.
        """
        super().__init__(db, "refresh_tokens")

    async def get_by_token(self, token: str) -> dict[str, Any] | None:
        """
        Retrieves a refresh token document by the token string.
        """
        docs = self.collection.where(filter=FieldFilter("token", "==", token)).limit(1).stream()
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                return data
        return None

    async def revoke_token(self, token_id: str):
        """
        Deletes a refresh token from the database.
        """
        await self.collection.document(token_id).delete()
