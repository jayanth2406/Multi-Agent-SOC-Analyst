"""FastAPI entry point for the Week 1 SOC Analyst proof of concept."""

from fastapi import FastAPI

from backend.models.schemas import Alert, TriageResult
from backend.services.triage_service import triage_service


app = FastAPI(
    title="Multi-Agent SOC Analyst - Week 1",
    description="Alert ingestion and deterministic structured triage proof of concept.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return a minimal liveness response."""

    return {"status": "ok"}


@app.post("/alerts/triage", response_model=TriageResult)
def triage_alert(alert: Alert) -> TriageResult:
    """Validate and triage one incoming security alert."""

    return triage_service.triage(alert)
