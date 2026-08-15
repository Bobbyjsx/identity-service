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

    async def send_verification_email(self, *, to: str, verify_url: str, app_name: str) -> None:
        await self.send_email(
            to=to,
            subject=f"{app_name}: verify your email",
            body=f"Verify your email by visiting: {verify_url}",
        )


class LoggingNotificationService(NotificationService):
    """Development/stub provider that logs instead of delivering email."""

    async def send_email(self, *, to: str, subject: str, body: str) -> None:
        print(f"[NotificationService][dev] to={to} subject={subject}")
