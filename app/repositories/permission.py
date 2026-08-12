from typing import Any

from google.cloud.firestore_v1.base_query import FieldFilter

from app.repositories.base import BaseRepository


class PermissionRepository(BaseRepository):
    def __init__(self, db):
        super().__init__(db, "permissions")

    async def get_by_name(self, app_id: str, name: str) -> dict[str, Any] | None:
        """
        Retrieves a permission by its name within an application.
        """
        docs = self.collection\
            .where(filter=FieldFilter("app_id", "==", app_id))\
            .where(filter=FieldFilter("name", "==", name))\
            .stream()
        async for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            return data
        return None

    async def get_by_app(self, app_id: str) -> list[dict[str, Any]]:
        """
        Retrieves all permissions for an application.
        """
        docs = self.collection.where(filter=FieldFilter("app_id", "==", app_id)).stream()
        permissions = []
        async for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            permissions.append(data)
        return permissions
