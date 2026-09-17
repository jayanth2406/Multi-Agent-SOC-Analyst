"""Input and output schemas for security alert triage."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Alert(BaseModel):
    """A normalized security alert received by the triage service."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(min_length=1, description="Stable identifier from the alert source")
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    host: str | None = None
    event_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    failed_attempts: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    """Structured, explainable output from the triage agent."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    classification: Literal[
        "likely_true_positive",
        "likely_false_positive",
        "needs_investigation",
    ]
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_summary: str
    extracted_iocs: list[str]
    required_investigations: list[str]
    recommended_next_step: str
