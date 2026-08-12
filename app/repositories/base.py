from typing import Any

from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter


class BaseRepository:
    def __init__(self, db: AsyncClient, collection_name: str):
        """
        Initializes the base repository with the given Firestore client and collection.
        """
        self.db = db
        self.collection = self.db.collection(collection_name)

    async def get(self, id: str) -> dict[str, Any] | None:
        """
        Retrieves a document by its ID from the collection.
        """
        doc = await self.collection.document(id).get()
        if doc.exists:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                return data
        return None

    async def create(self, data: dict[str, Any], id: str | None = None) -> dict[str, Any]:
        """
        Creates a new document in the collection, optionally with a specific ID.
        """
        if id:
            doc_ref = self.collection.document(id)
            await doc_ref.set(data)
        else:
            doc_ref = self.collection.document()
            await doc_ref.set(data)
            data["id"] = doc_ref.id
        return data

    async def get_by_field(self, field: str, value: Any) -> list[dict[str, Any]]:
        """
        Retrieves a list of documents that match a specific field-value equality.
        """
        docs = self.collection.where(filter=FieldFilter(field, "==", value)).stream()
        results = []
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                results.append(data)
        return results

class TenantRepository(BaseRepository):
    async def get_tenant_resource(self, app_id: str, id: str) -> dict[str, Any] | None:
        """
        Retrieves a document by ID ensuring it belongs to the specified tenant.
        """
        doc = await self.get(id)
        if doc and doc.get("app_id") == app_id:
            return doc
        return None

    async def get_by_tenant(self, app_id: str) -> list[dict[str, Any]]:
        """
        Retrieves all documents belonging to a specific tenant.
        """
        return await self.get_by_field("app_id", app_id)
