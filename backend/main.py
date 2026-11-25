"""FastAPI entry point for the Multi-Agent SOC Analyst system."""

from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException

from backend.agents.report_generator import IncidentReport
from backend.agents.triage_agent import get_triage_agent
from backend.models.schemas import Alert, SocAlert, TriageDecision, TriageResult
from backend.orchestration.graph import soc_orchestrator
from backend.services.hitl_simulator import AuditRecord, ReviewDecision, hitl_service
from backend.services.triage_service import triage_service

app = FastAPI(
    title="Multi-Agent SOC Analyst API",
    description="Autonomous Security Alert Triage, Correlation, Threat Intelligence, and Reporting.",
    version="0.2.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return a minimal liveness response."""
    return {"status": "ok"}


@app.post("/api/v1/triage", response_model=TriageDecision)
def triage_v1(alert: SocAlert) -> TriageDecision:
    """Triage one alert with the v1 Triage agent (taxonomy, severity rubric, light/full routing)."""
    return get_triage_agent().triage(alert)


@app.post("/api/v1/triage/batch", response_model=list[TriageDecision])
def triage_v1_batch(alerts: list[SocAlert]) -> list[TriageDecision]:
    """Triage a batch of alerts, in the order given."""
    agent = get_triage_agent()
    return [agent.triage(a) for a in alerts]


@app.post("/alerts/triage", response_model=TriageResult)
def triage_alert(alert: Alert) -> TriageResult:
    """Legacy keyword triage (old alert format). Use /api/v1/triage for the v1 agent."""
    return triage_service.triage(alert)


@app.post("/alerts/investigate", response_model=IncidentReport)
def investigate_alert(alert: Alert) -> IncidentReport:
    """Run full LangGraph multi-agent pipeline and queue report for human review."""
    try:
        initial_state = {
            "alert": alert,
            "triage_finding": None,
            "correlation_finding": None,
            "threat_intel_finding": None,
            "incident_report": None,
            "system1_used": False,
            "status": "started",
            "errors": [],
        }
        result = soc_orchestrator.invoke(initial_state)
        report = result.get("incident_report")
        if not report:
            raise HTTPException(status_code=500, detail="Failed to generate incident report.")

        # Queue report for analyst review
        hitl_service.submit_for_review(report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reviews/pending", response_model=Dict[str, IncidentReport])
def get_pending_reviews() -> Dict[str, IncidentReport]:
    """Retrieve all incident reports awaiting human analyst approval."""
    return hitl_service.pending_reviews


@app.post("/reviews/decision", response_model=AuditRecord)
def submit_decision(decision: ReviewDecision) -> AuditRecord:
    """Record human approval or rejection and execute safe simulation."""
    try:
        return hitl_service.record_decision(decision)
    except (ValueError, IndexError) as e:
        raise HTTPException(status_code=400, detail=str(e))
