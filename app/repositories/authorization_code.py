import asyncio
import logging
from typing import Any

from google.api_core.exceptions import Aborted
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.async_transaction import AsyncTransaction, async_transactional
from google.cloud.firestore_v1.base_query import FieldFilter

from app.repositories.base import BaseRepository

logger = logging.getLogger(__name__)


@async_transactional
async def _redeem_in_transaction(
    tx: AsyncTransaction,
    collection,
    code_id: str,
    code_hash: str,
    expected_status: str,
    used_at: str,
) -> bool:
    """
    Reads the code inside the transaction and atomically marks it used.
    The async_transactional decorator retries on commit conflicts, so
    concurrent redemption attempts can never both succeed.
    """
    ref = collection.document(code_id)
    query = collection.where(filter=FieldFilter("code_hash", "==", code_hash)).limit(1)
    async for doc in query.stream(transaction=tx):
        data = doc.to_dict() or {}
        if data.get("status") != expected_status:
            return False
        tx.update(ref, {"status": "used", "used_at": used_at})
        return True
    return False


class AuthorizationCodeRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        super().__init__(db, "authorization_codes")

    async def get_by_code_hash(self, code_hash: str) -> dict[str, Any] | None:
        """
        Retrieves an authorization code document by the hash of the raw code.
        """
        docs = self.collection.where(filter=FieldFilter("code_hash", "==", code_hash)).limit(1).stream()
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["id"] = doc.id
                return data
        return None

    async def mark_used_atomic(self, code_id: str, code_hash: str, expected_status: str, used_at: str) -> bool:
        """
        Atomically marks an authorization code as used (single-use guarantee).

        Returns False when the code is no longer active or a concurrent
        redemption already won. Infrastructure failures are logged and
        re-raised; they are not converted into invalid_grant.
        """
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return await _redeem_in_transaction(
                    self.db.transaction(), self.collection, code_id, code_hash, expected_status, used_at
                )
            except (Aborted, ValueError) as exc:
                last_error = exc
                latest = await self.get(code_id)
                if latest is None or latest.get("status") != expected_status:
                    return False
                await asyncio.sleep(0.05 * (attempt + 1))
            except Exception:
                logger.exception("authorization code redemption failed")
                raise
        logger.exception("authorization code redemption failed after contention", exc_info=last_error)
        raise last_error or RuntimeError("authorization code redemption failed")
