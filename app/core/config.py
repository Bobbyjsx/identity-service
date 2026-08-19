from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: str = "development"
    firestore_database: str = "(default)"
    google_application_credentials: str = "firebase-credentials.json"

    admin_secret: str = "changeme-in-prod"
    # Canonical issuer for access tokens, service tokens, ID tokens, and OIDC discovery.
    identity_issuer: str = "http://localhost:8002"
    private_key: str | None = None

    jwt_expiration_minutes: int = 15
    refresh_token_expiration_days: int = 30

    identity_ui_base_url: str = "http://localhost:3000"
    public_base_url: str = "http://localhost:8002"
    auth_session_expiration_minutes: int = 10
    oauth_authorization_code_expiration_minutes: int = 5
    password_reset_token_expiration_minutes: int = 30

    turnstile_secret_key: str = ""
    turnstile_hostnames: str = "localhost,127.0.0.1"  # comma-separated list
    turnstile_enabled: bool = True

    gcp_project_id: str = "project-atlas-501612"
    pubsub_topic_id: str = "platform-events"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
