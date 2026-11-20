"""LangGraph Multi-Agent SOC Analyst Coordinator.

Orchestrates the collaborative pipeline across Triage, Log Correlation,
Threat Intelligence, and Report Generation agents with conditional fast-paths.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from backend.agents.log_correlation import CorrelationResult, log_correlation_agent
from backend.agents.report_generator import IncidentReport, report_generation_agent
from backend.agents.system1_decision import system1_model
from backend.agents.threat_intel import ThreatIntelResult, threat_intel_agent
from backend.agents.triage import DeterministicTriageAgent
from backend.config import get_settings
from backend.models.schemas import Alert, TriageResult
from backend.providers.llm_provider import llm_provider

logger = logging.getLogger("agent_orchestration")


class SocAgentState(TypedDict):
    """Shared state across multi-agent nodes."""
    alert: Alert
    triage_finding: Optional[TriageResult]
    correlation_finding: Optional[CorrelationResult]
    threat_intel_finding: Optional[ThreatIntelResult]
    incident_report: Optional[IncidentReport]
    system1_used: bool
    status: str
    errors: List[str]


rules_triage = DeterministicTriageAgent()


def triage_node(state: SocAgentState) -> Dict[str, Any]:
    """Node 1: Triage using Hybrid System 1 / Rules / LLM strategy."""
    alert = state["alert"]
    settings = get_settings()
    triage_res: Optional[TriageResult] = None
    system1_used = False

    # Strategy 1: System 1 Fast Decision Model
    if settings.triage_mode in ("system1", "hybrid"):
        try:
            triage_res = system1_model.predict(alert)
            system1_used = True
        except Exception as e:
            logger.warning(f"System 1 decision failed: {e}. Falling back to rules.")

    # Strategy 2: Rules Baseline (fallback or explicit mode)
    if triage_res is None or settings.triage_mode == "rules":
        triage_res = rules_triage.triage(alert)
        system1_used = False

    # Strategy 3: Optional LLM escalation if configured and alert is ambiguous
    if settings.triage_mode == "llm" or (
        settings.triage_mode == "hybrid"
        and triage_res.classification == "needs_investigation"
        and llm_provider.is_configured
    ):
        prompt = (
            f"Analyze this security alert:\n"
            f"ID: {alert.alert_id}\nType: {alert.event_type}\nDesc: {alert.description}\n"
            f"Source: {alert.source_ip} -> Dest: {alert.destination_ip}\n"
            f"User: {alert.user} | Host: {alert.host}\nMetadata: {alert.metadata}\n"
            f"Classify strictly as likely_true_positive, likely_false_positive, or needs_investigation."
        )
        llm_res = llm_provider.structured_completion(prompt, TriageResult)
        if llm_res:
            triage_res = llm_res
            system1_used = False

    return {
        "triage_finding": triage_res,
        "system1_used": system1_used,
        "status": "triaged",
    }


def triage_router(state: SocAgentState) -> str:
    """Conditional Edge: Fast-path benign false positives or trigger full investigation."""
    finding = state["triage_finding"]
    if finding and finding.classification == "likely_false_positive" and finding.confidence >= 0.92:
        return "fast_path_report"
    return "investigate"


def correlation_node(state: SocAgentState) -> Dict[str, Any]:
    """Node 2: Telemetry Correlation across Auth, Network, and Endpoint logs."""
    alert = state["alert"]
    res = log_correlation_agent.investigate(alert)
    return {
        "correlation_finding": res,
        "status": "correlated",
    }


def threat_intel_node(state: SocAgentState) -> Dict[str, Any]:
    """Node 3: Threat Intelligence enrichment and MITRE ATT&CK mapping."""
    alert = state["alert"]
    triage = state["triage_finding"]
    iocs = triage.extracted_iocs if triage else []
    res = threat_intel_agent.investigate(alert, iocs)
    return {
        "threat_intel_finding": res,
        "status": "threat_intel_enriched",
    }


def report_node(state: SocAgentState) -> Dict[str, Any]:
    """Node 4: Report generation and remediation proposal synthesis."""
    alert = state["alert"]
    triage = state["triage_finding"]
    correlation = state.get("correlation_finding")
    threat_intel = state.get("threat_intel_finding")

    # If fast-pathed, generate minimal correlation/intel mocks
    if correlation is None:
        correlation = log_correlation_agent.investigate(alert)
    if threat_intel is None:
        threat_intel = threat_intel_agent.investigate(alert, triage.extracted_iocs if triage else [])

    report = report_generation_agent.generate(alert, triage, correlation, threat_intel)
    return {
        "incident_report": report,
        "status": "completed",
    }


# Build LangGraph Workflow
def create_soc_graph():
    builder = StateGraph(SocAgentState)

    builder.add_node("triage", triage_node)
    builder.add_node("correlation", correlation_node)
    builder.add_node("threat_intel", threat_intel_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "triage")
    builder.add_conditional_edges(
        "triage",
        triage_router,
        {
            "fast_path_report": "report",
            "investigate": "correlation",
        },
    )
    builder.add_edge("correlation", "threat_intel")
    builder.add_edge("threat_intel", "report")
    builder.add_edge("report", END)

    return builder.compile()


soc_orchestrator = create_soc_graph()
