"""Unit tests for the transparent deterministic triage baseline."""

from datetime import datetime, timezone

import pytest

from backend.agents.triage import DeterministicTriageAgent
from backend.config import Settings
from backend.models.schemas import Alert
from backend.services.triage_service import TriageService


def make_alert(**overrides: object) -> Alert:
    """Build a valid alert with convenient test defaults."""

    data: dict[str, object] = {
        "alert_id": "TEST-001",
        "timestamp": datetime.now(timezone.utc),
        "source_ip": "185.10.20.30",
        "destination_ip": "10.0.0.23",
        "user": "alice",
        "host": "host-23",
        "event_type": "authentication",
        "description": "Security event",
        "failed_attempts": None,
        "metadata": {},
    }
    data.update(overrides)
    return Alert.model_validate(data)


@pytest.fixture
def agent() -> DeterministicTriageAgent:
    return DeterministicTriageAgent()


def test_brute_force_alert_is_categorized_correctly(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(
        make_alert(
            description="20 failed SSH attempts followed by successful login",
            failed_attempts=20,
            metadata={"login_success_after_failures": True},
        )
    )

    assert result.category == "brute_force"
    assert result.classification == "likely_true_positive"


def test_success_after_failed_logins_has_high_severity(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(
        make_alert(
            description="Repeated failed SSH logins followed by success",
            failed_attempts=8,
            metadata={"login_success_after_failures": True},
        )
    )

    assert result.severity in {"high", "critical"}


def test_benign_login_typo_is_not_critical(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(
        make_alert(
            description="Two mistyped passwords from the employee workstation",
            failed_attempts=2,
        )
    )

    assert result.classification == "likely_false_positive"
    assert result.severity != "critical"


def test_port_scan_gets_correct_category(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(
        make_alert(
            event_type="network_reconnaissance",
            description="One source probes many ports rapidly",
            metadata={"ports_contacted": 25},
        )
    )

    assert result.category == "port_scan"
    assert result.classification == "likely_true_positive"


def test_unknown_event_needs_investigation(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(
        make_alert(event_type="unclassified_event", description="An unfamiliar event was observed")
    )

    assert result.classification == "needs_investigation"
    assert result.category == "unknown"


def test_confidence_stays_between_zero_and_one(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(make_alert(description="Suspicious outbound connection", event_type="outbound_connection"))

    assert 0.0 <= result.confidence <= 1.0


def test_iocs_include_structured_fields_and_hash(agent: DeterministicTriageAgent) -> None:
    result = agent.triage(make_alert(metadata={"sha256": "a" * 64}))

    assert result.extracted_iocs == [
        "185.10.20.30",
        "10.0.0.23",
        "host-23",
        "alice",
        "a" * 64,
    ]


def test_unavailable_llm_mode_falls_back_to_rules() -> None:
    service = TriageService(Settings(triage_mode="llm", llm_api_key="test-only"))

    result = service.triage(
        make_alert(
            description="20 failed SSH attempts followed by successful login",
            failed_attempts=20,
            metadata={"login_success_after_failures": True},
        )
    )

    assert result.category == "brute_force"
