"""Human-in-the-Loop Review Gate and Safe Action Simulator.

Enforces human authorization before executing any remediation action.
Actions are executed strictly against a simulator and recorded to an
append-only cryptographic audit trail in locals/logs/audit_trail.jsonl.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from backend.agents.report_generator import ActionProposal, IncidentReport

logger = logging.getLogger("hitl_simulator")
AUDIT_LOG_PATH = Path("locals/logs/audit_trail.jsonl")
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


class ReviewDecision(BaseModel):
    """Analyst review decision."""
    case_id: str
    action_index: int
    decision: Literal["approved", "rejected", "modified"]
    reviewer_id: str
    reviewer_notes: str
    modified_action: Optional[ActionProposal] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditRecord(BaseModel):
    """Immutable audit record of simulated action execution."""
    execution_id: str
    timestamp: str
    case_id: str
    action_type: str
    target_entity: str
    decision: str
    reviewer_id: str
    is_simulation: bool = True
    payload_hash: str
    status: str  # SIMULATED_SUCCESS, REJECTED, FAILED


class HitlSimulatorService:
    """Manages the Human-in-the-Loop approval gate and simulated execution."""

    def __init__(self):
        self.pending_reviews: Dict[str, IncidentReport] = {}
        self.decision_history: List[ReviewDecision] = []

    def submit_for_review(self, report: IncidentReport) -> str:
        """Queue a completed investigation report for human analyst review."""
        case_id = report.report_id
        self.pending_reviews[case_id] = report
        logger.info(f"Report {case_id} queued for analyst review with {len(report.proposed_actions)} proposed action(s).")
        return case_id

    def record_decision(self, decision: ReviewDecision) -> AuditRecord:
        """Record analyst decision and trigger safe simulated execution if approved."""
        case_id = decision.case_id
        report = self.pending_reviews.get(case_id)
        if not report:
            raise ValueError(f"Report {case_id} not found in pending review queue.")

        if decision.action_index >= len(report.proposed_actions):
            raise IndexError(f"Action index {decision.action_index} out of range.")

        action = (
            decision.modified_action
            if decision.decision == "modified" and decision.modified_action
            else report.proposed_actions[decision.action_index]
        )

        # Compute payload hash
        payload_data = f"{case_id}:{action.action_type}:{action.target_entity}:{decision.timestamp}"
        payload_hash = hashlib.sha256(payload_data.encode()).hexdigest()
        execution_id = f"EXEC-{payload_hash[:12].upper()}"

        status = "SIMULATED_SUCCESS" if decision.decision in ("approved", "modified") else "REJECTED"

        audit_record = AuditRecord(
            execution_id=execution_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            case_id=case_id,
            action_type=action.action_type,
            target_entity=action.target_entity,
            decision=decision.decision,
            reviewer_id=decision.reviewer_id,
            is_simulation=True,
            payload_hash=payload_hash,
            status=status,
        )

        # Append to audit trail
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(audit_record.model_dump_json() + "\n")

        self.decision_history.append(decision)
        logger.info(f"Action {action.action_type} for {action.target_entity} resolved: {status} by {decision.reviewer_id}.")
        return audit_record


hitl_service = HitlSimulatorService()
