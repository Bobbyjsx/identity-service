class NotificationService:
    """
    Clean integration boundary for out-of-band notifications (password reset
    emails, email verification emails).

    Email delivery intentionally does NOT live inside Identity Service.
    Production deployments should provide a provider (an external notification
    microservice, SES, SendGrid, etc.) that implements `send_email`.

    The development implementation only logs the notification payload, never
    secrets in production mode. Reset tokens themselves are never logged.
    """

    async def send_email(self, *, to: str, subject: str, body: str) -> None:
        raise NotImplementedError(
            "NotificationService.send_email must be implemented by a provider"
        )

    async def send_password_reset_email(self, *, to: str, reset_url: str, app_name: str) -> None:
        await self.send_email(
            to=to,
            subject=f"{app_name}: reset your password",
            body=f"Reset your password by visiting: {reset_url}",
        )

    async def send_welcome_email(self, *, to: str, app_name: str, first_name: str | None = None) -> None:
        await self.send_email(to=to, subject=f"Welcome to {app_name}", body=f"Welcome!")

    async def send_verification_email(self, *, to: str, otp: str, app_name: str) -> None:
        await self.send_email(
            to=to,
            subject=f"{app_name}: verify your email",
            body=f"Your email verification code is: {otp}\n\nThis code expires in 30 minutes.",
        )


class LoggingNotificationService(NotificationService):
    """Development/stub provider that logs instead of delivering email."""

    async def send_email(self, *, to: str, subject: str, body: str) -> None:
        print(f"[NotificationService][dev] to={to} subject={subject}\n{body}")

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)

class PubSubNotificationService(NotificationService):
    """
    Publishes authentication events (like verify email, reset password) to a 
    Google Cloud Pub/Sub topic so that the centralized Notification Service 
    can render and deliver them.
    """

    def __init__(self, project_id: str, topic_id: str):
        self.project_id = project_id
        self.topic_id = topic_id
        self.publisher = pubsub_v1.PublisherClient()
        self.topic_path = self.publisher.topic_path(project_id, topic_id)

    async def _publish_event(self, event_type: str, app_id: str, data: dict[str, Any], subject: str | None = None) -> None:
        event = {
            "id": f"evt-{uuid.uuid4().hex}",
            "type": event_type,
            "version": 1,
            "source": app_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        if subject:
            event["subject"] = subject
            
        try:
            future = self.publisher.publish(
                self.topic_path, 
                json.dumps(event).encode("utf-8")
            )
            # Await the publish
            message_id = future.result(timeout=5)
            logger.info("Published %s event to Pub/Sub with message ID: %s", event_type, message_id)
        except Exception as exc:
            logger.error("Failed to publish %s event to Pub/Sub: %s", event_type, exc)
            # We don't raise here, so we don't break the auth flow if notifications are down
            
    async def send_email(self, *, to: str, subject: str, body: str) -> None:
        # We don't implement the raw text fallback here
        pass

    async def send_password_reset_email(self, *, to: str, reset_url: str, app_name: str, app_id: str | None = None, first_name: str | None = None) -> None:
        data = {
            "email": to,
            "reset_url": reset_url,
            "expiration_minutes": 30,
        }
        if first_name:
            data["first_name"] = first_name
            
        await self._publish_event("user.password_reset_requested", app_id or "identity-service", data)

    async def send_verification_email(self, *, to: str, otp: str, app_name: str, app_id: str | None = None, first_name: str | None = None) -> None:
        data = {
            "email": to,
            "otp": otp,
            "expiration_minutes": 30,
        }
        if first_name:
            data["first_name"] = first_name
            
        await self._publish_event("user.email_verification_requested", app_id or "identity-service", data)
        
    async def send_welcome_email(self, *, to: str, app_name: str, app_id: str | None = None, first_name: str | None = None) -> None:
        data = {
            "email": to,
            "body": f"Welcome to {app_name}! Your email has been successfully verified.",
            "title": f"Welcome to {app_name}",
        }
        if first_name:
            data["first_name"] = first_name
            
        await self._publish_event("general.notification", app_id or "identity-service", data, subject=f"Welcome to {app_name}!")
