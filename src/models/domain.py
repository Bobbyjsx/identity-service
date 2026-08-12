import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.status import Status


class ApplicationModel:
    @staticmethod
    def create(name: str, description: str | None = None) -> dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "client_id": f"app_{uuid.uuid4().hex}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": Status.ACTIVE,
        }


class ApplicationCredentialModel:
    @staticmethod
    def create(app_id: str, hashed_secret: str) -> dict[str, Any]:
        return {
            "app_id": app_id,
            "hashed_secret": hashed_secret,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": Status.ACTIVE,
        }


class UserModel:
    @staticmethod
    def create(app_id: str, email: str, hashed_password: str) -> dict[str, Any]:
        return {
            "app_id": app_id,
            "email": email.lower(),
            "hashed_password": hashed_password,
            "roles": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
