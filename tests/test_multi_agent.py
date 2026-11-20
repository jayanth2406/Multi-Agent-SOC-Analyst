"""Unit and integration tests for the Multi-Agent SOC Analyst architecture."""

from datetime import datetime

from backend.agents.log_correlation import log_correlation_agent
from backend.agents.report_generator import report_generation_agent
from backend.agents.system1_decision import system1_model
from backend.agents.threat_intel import threat_intel_agent
from backend.models.schemas import Alert
from backend.orchestration.graph import soc_orchestrator
from backend.services.hitl_simulator import ReviewDecision, hitl_service


def sample_brute_force_alert() -> Alert:
    return Alert(
        alert_id="TEST-BF-001",
        timestamp=datetime.fromisoformat("2026-11-20T10:00:00"),
        source_ip="185.220.101.5",
        destination_ip="10.0.0.12",
        user="alice.smith",
        host="dc-01.corp",
        event_type="authentication_failure",
        description="Repeated failed SSH logins followed by successful logon.",
        failed_attempts=25,
        metadata={
            "login_success_after_failures": True,
            "ground_truth_category": "brute_force",
            "ground_truth_classification": "likely_true_positive",
            "ground_truth_severity": "high",
        },
    )


def sample_benign_alert() -> Alert:
    return Alert(
        alert_id="TEST-BENIGN-001",
        timestamp=datetime.fromisoformat("2026-11-20T10:05:00"),
        source_ip="10.0.1.50",
        destination_ip="10.0.1.10",
        user="nessus_svc",
        host="dc-01.corp",
        event_type="scheduled_maintenance",
        description="Internal vulnerability scanner Nessus running approved audit.",
        failed_attempts=0,
        metadata={
            "approved_activity": True,
            "ground_truth_category": "approved_activity",
            "ground_truth_classification": "likely_false_positive",
            "ground_truth_severity": "low",
        },
    )


def test_system1_decision_fast_inference():
    alert = sample_brute_force_alert()
    res = system1_model.predict(alert)
    assert res.classification == "likely_true_positive"
    assert res.category == "brute_force"
    assert 0.0 <= res.confidence <= 1.0
    assert "185.220.101.5" in res.extracted_iocs


def test_log_correlation_extracts_timeline():
    alert = sample_brute_force_alert()
    res = log_correlation_agent.investigate(alert)
    assert res.correlated_events_count >= 2
    assert any("authentication_logs" in src for src in res.covered_log_sources)
    assert len(res.timeline) >= 2


def test_threat_intel_privacy_guard_and_mitre():
    alert = sample_brute_force_alert()
    iocs = ["185.220.101.5", "10.0.0.12", "alice.smith", "dc-01.corp"]
    res = threat_intel_agent.investigate(alert, iocs)

    # 185.220.101.5 is public
    public_ioc = next(e for e in res.enriched_iocs if e.ioc_value == "185.220.101.5")
    assert not public_ioc.is_internal
    assert public_ioc.reputation_score > 0.5

    # 10.0.0.12 is private RFC1918
    private_ioc = next(e for e in res.enriched_iocs if e.ioc_value == "10.0.0.12")
    assert private_ioc.is_internal
    assert private_ioc.verdict == "internal_asset"

    # Pinned MITRE technique
    assert any(m.technique_id == "T1110" for m in res.mitre_attack_mappings)


def test_langgraph_full_pipeline_execution():
    alert = sample_brute_force_alert()
    state = {
        "alert": alert,
        "triage_finding": None,
        "correlation_finding": None,
        "threat_intel_finding": None,
        "incident_report": None,
        "system1_used": False,
        "status": "started",
        "errors": [],
    }
    result = soc_orchestrator.invoke(state)
    report = result["incident_report"]
    assert report is not None
    assert report.disposition == "confirmed_incident"
    assert len(report.timeline_summary) >= 2
    assert len(report.proposed_actions) >= 1
    assert "T1110" in report.mitre_techniques[0]


def test_hitl_approval_and_simulation():
    alert = sample_brute_force_alert()
    state = {
        "alert": alert,
        "triage_finding": None,
        "correlation_finding": None,
        "threat_intel_finding": None,
        "incident_report": None,
        "system1_used": False,
        "status": "started",
        "errors": [],
    }
    res = soc_orchestrator.invoke(state)
    report = res["incident_report"]

    case_id = hitl_service.submit_for_review(report)
    decision = ReviewDecision(
        case_id=case_id,
        action_index=0,
        decision="approved",
        reviewer_id="analyst_lead_01",
        reviewer_notes="Confirmed unauthorized brute-force attack from external IP. Approved host isolation.",
    )
    audit = hitl_service.record_decision(decision)
    assert audit.status == "SIMULATED_SUCCESS"
    assert audit.is_simulation is True
    assert audit.reviewer_id == "analyst_lead_01"
