from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str = "IAM Lite"
    APP_ENV: str = "development"
    DEBUG: bool = False

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ID_TOKEN_EXPIRE_MINUTES: int = 60

    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"

    OAUTH2_ISSUER: str = "http://localhost:8000"
    OAUTH2_AUDIENCE: str = "iam-lite-api"

    FIRST_ADMIN_EMAIL: str = "admin@iam-lite.local"
    FIRST_ADMIN_PASSWORD: str = "Admin@2025!"


@lru_cache
def get_settings() -> Settings:
    return Settings()
