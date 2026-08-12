from typing import Any

from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from app.repositories.base import TenantRepository


class UserRepository(TenantRepository):
    def __init__(self, db: AsyncClient):
        """
        Initializes the UserRepository.
        """
        super().__init__(db, "users")
        
    async def get_by_email(self, app_id: str, email: str) -> dict[str, Any] | None:
        """
        Retrieves a user by their email, ensuring it's scoped to the given tenant.
        """
        docs = self.collection.where(filter=FieldFilter("app_id", "==", app_id)).where(filter=FieldFilter("email", "==", email.lower())).stream()
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                return data
        return None
