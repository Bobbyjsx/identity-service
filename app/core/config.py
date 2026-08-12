from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: str = "development"
    firestore_database: str = "(default)"
    google_application_credentials: str = "firebase-credentials.json"

    jwt_expiration_minutes: int = 15
    refresh_token_expiration_days: int = 30

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
