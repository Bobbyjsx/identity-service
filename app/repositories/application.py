from typing import Any

from google.cloud.firestore_v1.async_client import AsyncClient

from app.repositories.base import BaseRepository


class ApplicationRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        """
        Initializes the ApplicationRepository.
        """
        super().__init__(db, "applications")

    async def get_by_client_id(self, client_id: str) -> dict[str, Any] | None:
        """
        Retrieves an application by its client_id.
        """
        docs = await self.get_by_field("client_id", client_id)
        return docs[0] if docs else None


class ApplicationCredentialRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        """
        Initializes the ApplicationCredentialRepository.
        """
        super().__init__(db, "application_credentials")
