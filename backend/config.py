"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the Multi-Agent SOC Analyst system."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Execution Mode: rules | llm | system1 | hybrid
    triage_mode: str = Field(default="hybrid")
    orchestrator_type: str = Field(default="langgraph")

    # OpenAI-Compatible API Configuration
    openai_api_key: str | None = None
    openai_base_url: str = Field(default="https://api.openai.com/v1")
    llm_model: str = Field(default="gpt-4o-mini")

    # Legacy alias support
    llm_api_key: str | None = None

    # Embeddings & RAG
    embedding_model: str = Field(default="sentence-transformers/all-MiniLM-L6-v2")

    # Local Small System 1 Decision Model (<500MB)
    system1_model_path: str = Field(default="models/system1_triage.joblib")
    system1_confidence_threshold: float = Field(default=0.85)
    system1_architecture: str = Field(default="statistical")  # "statistical" | "neural" | "hybrid"
    system1_neural_model_id: str = Field(default="typeform/distilbert-base-uncased-mnli")

    # Storage paths
    data_dir: str = Field(default="data")
    local_data_dir: str = Field(default="data")
    local_logs_dir: str = Field(default="locals/logs")
    benchmark_output_dir: str = Field(default="benchmarks")

    def get_effective_api_key(self) -> str | None:
        """Return the API key from either openai_api_key or llm_api_key."""
        return self.openai_api_key or self.llm_api_key


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""
    return Settings()
