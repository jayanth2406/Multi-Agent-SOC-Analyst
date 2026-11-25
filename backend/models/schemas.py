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


# --------------------------------------------------------------------------- v1 (requirements spec)

from pydantic import AliasChoices  # noqa: E402


class SocAlert(BaseModel):
    """An incoming alert in the v1 format (FR-ING-1 to 3).

    This is the format of the PoC alert set. The older field names
    `source_ip` and `destination_ip` are accepted and normalised. Unknown
    fields are kept, so the raw alert survives normalisation.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    alert_id: str = Field(min_length=1)
    timestamp: datetime
    rule_id: str = Field(min_length=1, description="The detection rule that fired, e.g. R-NET-SCAN")
    rule_name: str | None = None
    source_system: str | None = None
    description: str = Field(min_length=1)
    src_ip: str | None = Field(default=None, validation_alias=AliasChoices("src_ip", "source_ip"))
    dst_ip: str | None = Field(default=None, validation_alias=AliasChoices("dst_ip", "destination_ip"))
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    service: str | None = None
    host: str | None = None
    user: str | None = None
    users: list[str] | None = None
    process: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    observables: dict[str, Any] = Field(default_factory=dict)


class IndicatorSet(BaseModel):
    """IOCs pulled from the alert (FR-TRI-3). Internal IPs are kept apart: they never go to outside feeds."""

    external_ips: list[str] = Field(default_factory=list)
    internal_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)


class TriageDecision(BaseModel):
    """The Triage agent's output (FR-TRI-1 to 6)."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    category: Literal["C1", "C2", "C3", "C4", "C5", "C6", "C7", "B1", "B2", "U0"]
    category_name: str
    disposition: Literal["TP", "BTP", "FP", "needs_investigation"]
    confidence: float = Field(ge=0.0, le=1.0)
    stage: int = Field(ge=0, le=4, description="Provisional attack stage")
    asset_tier: Literal["Low", "Standard", "High", "Critical"]
    severity: Literal["Informational", "Low", "Medium", "High", "Critical"]
    investigation: Literal["light", "full"]
    safeguards_fired: list[str]
    safeguards_not_checked: list[str]
    indicators: IndicatorSet
    log_sources: list[Literal["network", "auth", "endpoint"]]
    reasoning_summary: str
    decided_by: Literal["rules", "model", "rules_only_fallback"]
    model_version: str | None = None
    normalised_alert: dict[str, Any]
