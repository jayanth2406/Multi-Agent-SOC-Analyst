"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the Week 1 triage service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    triage_mode: str = Field(default="rules", pattern="^(rules|llm)$")
    llm_api_key: str | None = None
    llm_model: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""

    return Settings()
