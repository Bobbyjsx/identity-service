import asyncio
from datetime import datetime, timezone
from typing import Any

from google.api_core.exceptions import Aborted
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.async_transaction import AsyncTransaction, async_transactional
from google.cloud.firestore_v1.base_query import FieldFilter

from app.core.errors import OAuthError
from app.repositories.base import BaseRepository
from app.schemas.auth_session import VALID_TRANSITIONS


class SessionClaimRejected(Exception):
    """The session could not be claimed; `status` is the effective current state."""

    def __init__(self, status: str):
        self.status = status
        super().__init__(status)


def oauth_error_for_session_status(status: str) -> OAuthError:
    if status == "missing":
        return OAuthError("invalid_session", "Session not found", status_code=404)
    if status == "expired":
        return OAuthError("session_expired", "Authorization session has expired")
    if status == "completed":
        return OAuthError("session_completed", "Session is already completed")
    if status == "cancelled":
        return OAuthError("session_cancelled", "Session is already cancelled")
    if status == "authenticated":
        return OAuthError("invalid_session_state", "Session is already in progress")
    return OAuthError(
        "invalid_session_state",
        "Operation not allowed in the current session state",
    )


def _effective_stored_status(data: dict[str, Any]) -> str:
    current = data.get("status") or "pending"
    if current in {"completed", "cancelled"}:
        return current
    try:
        expires_at = datetime.fromisoformat(data["expires_at"])
    except (ValueError, TypeError, KeyError):
        return "expired"
    if datetime.now(timezone.utc) > expires_at:
        return "expired"
    return current


async def _read_tx_in_session(tx: AsyncTransaction, collection, session_id: str) -> dict[str, Any]:
    # AsyncTransaction.get(ref) is unusable in this client version (async_generator).
    query = collection.where(filter=FieldFilter("id", "==", session_id)).limit(1)
    async for doc in query.stream(transaction=tx):
        data = doc.to_dict() or {}
        data["id"] = doc.id
        return data
    raise SessionClaimRejected("missing")


def _assert_transition(current: str, new_status: str) -> None:
    if new_status not in VALID_TRANSITIONS.get(current, frozenset()):
        raise SessionClaimRejected(current)


@async_transactional
async def _claim_in_session(
    tx: AsyncTransaction,
    collection,
    session_id: str,
    expected_statuses: set[str],
    new_status: str,
    updates: dict[str, Any],
) -> dict[str, Any]:
    data = await _read_tx_in_session(tx, collection, session_id)
    current = _effective_stored_status(data)
    if current not in expected_statuses:
        raise SessionClaimRejected(current)
    _assert_transition(current, new_status)
    payload = {"status": new_status, **updates}
    tx.update(collection.document(data["id"]), payload)
    data.update(payload)
    return data


@async_transactional
async def _complete_with_code_in_session(
    tx: AsyncTransaction,
    tx_collection,
    code_collection,
    session_id: str,
    expected_status: str,
    session_updates: dict[str, Any],
    code_id: str,
    code_data: dict[str, Any],
) -> dict[str, Any]:
    data = await _read_tx_in_session(tx, tx_collection, session_id)
    current = _effective_stored_status(data)
    if current != expected_status:
        raise SessionClaimRejected(current)
    _assert_transition(current, "completed")
    tx.update(tx_collection.document(data["id"]), session_updates)
    tx.set(code_collection.document(code_id), code_data)
    data.update(session_updates)
    return data


class AuthSessionRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        super().__init__(db, "auth_sessions")

    def _lost_race_or_reraise(
        self,
        exc: Exception,
        latest: dict[str, Any] | None,
        expected: set[str],
    ) -> None:
        if latest:
            status = _effective_stored_status(latest)
            if status not in expected:
                raise oauth_error_for_session_status(status) from exc
        raise OAuthError(
            "server_error",
            "An unexpected error occurred",
            status_code=500,
        ) from exc

    async def claim_session(
        self,
        session_id: str,
        expected_status: str | set[str] = "pending",
        new_status: str = "authenticated",
        updates: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Atomically progress a session from `expected_status` to `new_status`.

        Only one concurrent caller can win the claim. Losers receive an
        OAuthError derived from the status the winner left behind.
        """
        expected = {expected_status} if isinstance(expected_status, str) else set(expected_status)
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return await _claim_in_session(
                    self.db.transaction(),
                    self.collection,
                    session_id,
                    expected,
                    new_status,
                    updates or {},
                )
            except SessionClaimRejected as exc:
                raise oauth_error_for_session_status(exc.status) from exc
            except (Aborted, ValueError) as exc:
                last_error = exc
                latest = await self.get(session_id)
                if latest and _effective_stored_status(latest) not in expected:
                    raise oauth_error_for_session_status(_effective_stored_status(latest)) from exc
                await asyncio.sleep(0.05 * (attempt + 1))
        self._lost_race_or_reraise(last_error or RuntimeError("claim failed"), await self.get(session_id), expected)
        raise RuntimeError("claim failed")

    async def complete_with_code(
        self,
        session_id: str,
        expected_status: str,
        session_updates: dict[str, Any],
        code_collection: Any,
        code_id: str,
        code_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Atomically claim the session into `completed` and persist the
        authorization code. Only one concurrent caller can issue a code.
        """
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return await _complete_with_code_in_session(
                    self.db.transaction(),
                    self.collection,
                    code_collection,
                    session_id,
                    expected_status,
                    session_updates,
                    code_id,
                    code_data,
                )
            except SessionClaimRejected as exc:
                raise oauth_error_for_session_status(exc.status) from exc
            except (Aborted, ValueError) as exc:
                last_error = exc
                latest = await self.get(session_id)
                if latest and _effective_stored_status(latest) != expected_status:
                    raise oauth_error_for_session_status(_effective_stored_status(latest)) from exc
                await asyncio.sleep(0.05 * (attempt + 1))
        self._lost_race_or_reraise(
            last_error or RuntimeError("complete failed"),
            await self.get(session_id),
            {expected_status},
        )
        raise RuntimeError("complete failed")
