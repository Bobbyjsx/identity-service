from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: str = "development"
    firestore_database: str = "(default)"
    google_application_credentials: str = "firebase-credentials.json"

    admin_secret: str = "changeme-in-prod"
    jwt_issuer: str = "urn:identity-service"
    private_key: str | None = None

    jwt_expiration_minutes: int = 15
    refresh_token_expiration_days: int = 30

    # Hosted OAuth / OIDC flow
    identity_ui_base_url: str = "http://localhost:3000"
    public_base_url: str = "http://localhost:8002"
    oauth_transaction_expiration_minutes: int = 10
    oauth_authorization_code_expiration_minutes: int = 5
    password_reset_token_expiration_minutes: int = 30
    oidc_issuer: str = "http://localhost:8002"

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
