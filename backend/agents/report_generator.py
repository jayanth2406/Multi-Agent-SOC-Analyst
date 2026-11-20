"""Report-Generation Agent.

Synthesizes triage findings, log correlation timelines, and threat intelligence
into an authoritative, evidence-cited incident report with recommended remediation actions.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.agents.log_correlation import CorrelationResult
from backend.agents.threat_intel import ThreatIntelResult
from backend.models.schemas import Alert, TriageResult
from backend.providers.llm_provider import llm_provider


class ActionProposal(BaseModel):
    """Specific remediation action requiring human approval."""
    action_type: str  # isolate_host, block_ip, reset_credentials, disable_user, close_benign
    target_entity: str
    rationale: str
    risk_level: str  # low, medium, high
    evidence_ids: List[str]


class IncidentReport(BaseModel):
    """Full structured incident report."""
    report_id: str
    alert_id: str
    timestamp: str
    disposition: str  # confirmed_incident, benign_activity, false_positive, inconclusive
    severity: str  # low, medium, high, critical
    confidence_score: float
    executive_summary: str
    mitre_techniques: List[str]
    timeline_summary: List[str]
    affected_internal_assets: List[str]
    external_threat_indicators: List[str]
    evidence_citations: List[str]
    proposed_actions: List[ActionProposal]


class ReportGenerationAgent:
    """Produces verified, human-readable structured SOC incident reports."""

    def generate(
        self,
        alert: Alert,
        triage: TriageResult,
        correlation: CorrelationResult,
        threat_intel: ThreatIntelResult,
    ) -> IncidentReport:
        """Synthesize multi-agent findings into a complete incident report."""
        report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"

        # Determine disposition
        if triage.classification == "likely_false_positive" or triage.category in ("approved_activity", "user_typo"):
            disposition = "false_positive"
        elif threat_intel.highest_threat_score >= 0.8 or triage.severity in ("high", "critical"):
            disposition = "confirmed_incident"
        else:
            disposition = "inconclusive"

        # Collect internal vs external assets
        internal_assets = [e.ioc_value for e in threat_intel.enriched_iocs if e.is_internal]
        external_threats = [e.ioc_value for e in threat_intel.enriched_iocs if not e.is_internal and e.reputation_score > 0.5]

        # Evidence citations
        citations = [event.evidence_id for event in correlation.timeline]

        # Timeline strings
        timeline_entries = [
            f"[{e.timestamp}] {e.action} ({e.source_type.upper()}): {e.details} [Ref: {e.evidence_id}]"
            for e in correlation.timeline
        ]

        # Proposed remediation actions for Human-in-the-Loop review
        proposed_actions: List[ActionProposal] = []
        if disposition == "confirmed_incident":
            if alert.host:
                proposed_actions.append(ActionProposal(
                    action_type="isolate_host",
                    target_entity=alert.host,
                    rationale=f"Contain potential lateral movement on host {alert.host}.",
                    risk_level="high",
                    evidence_ids=[e for e in citations if "EDR" in e or "AUTH" in e],
                ))
            for ext in external_threats:
                proposed_actions.append(ActionProposal(
                    action_type="block_ip",
                    target_entity=ext,
                    rationale=f"Block malicious egress/ingress traffic to {ext} at perimeter firewall.",
                    risk_level="medium",
                    evidence_ids=[e for e in citations if "NET" in e],
                ))
            if alert.user:
                proposed_actions.append(ActionProposal(
                    action_type="reset_credentials",
                    target_entity=alert.user,
                    rationale=f"Compromised credential risk for account {alert.user}.",
                    risk_level="low",
                    evidence_ids=[e for e in citations if "AUTH" in e],
                ))
        else:
            proposed_actions.append(ActionProposal(
                action_type="close_benign",
                target_entity=alert.alert_id,
                rationale="Activity verified as approved or non-threatening.",
                risk_level="low",
                evidence_ids=[],
            ))

        mitre_list = [f"{m.technique_id} - {m.technique_name} ({m.tactic})" for m in threat_intel.mitre_attack_mappings]

        # Executive summary
        summary = (
            f"Investigation for alert '{alert.alert_id}' ({alert.event_type}) completed. "
            f"Disposition: {disposition.upper()}. Category: {triage.category}. Severity: {triage.severity.upper()}. "
            f"Identified {len(external_threats)} hostile external indicators and {len(internal_assets)} affected internal entities. "
            f"{len(proposed_actions)} containment action(s) submitted for analyst review."
        )

        return IncidentReport(
            report_id=report_id,
            alert_id=alert.alert_id,
            timestamp=str(alert.timestamp),
            disposition=disposition,
            severity=triage.severity,
            confidence_score=triage.confidence,
            executive_summary=summary,
            mitre_techniques=mitre_list,
            timeline_summary=timeline_entries,
            affected_internal_assets=internal_assets,
            external_threat_indicators=external_threats,
            evidence_citations=citations,
            proposed_actions=proposed_actions,
        )


report_generation_agent = ReportGenerationAgent()
