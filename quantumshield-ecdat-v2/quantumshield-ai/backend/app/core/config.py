import os
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "QuantumShield AI"
    environment: str = os.environ.get("ENVIRONMENT", "development")
    mongodb_uri: str = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_db: str = os.environ.get("MONGODB_DB", "quantumshield")
    redis_uri: str = os.environ.get("REDIS_URI", "redis://localhost:6379/0")
    anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")
    jwt_secret: str = os.environ.get("JWT_SECRET", "change-me-in-production")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    cors_origins: list[str] = ["*"]

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
