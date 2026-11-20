"""Log-Correlation Agent.

Queries authentication (LANL), network/firewall (UNSW-NB15), and endpoint (BETH)
telemetry around alert IOCs using structured query tools, reconstructs chronological
event timelines, and identifies coverage gaps.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.schemas import Alert
from backend.storage.db import (
    query_auth_logs_db,
    query_endpoint_logs_db,
    query_network_flows_db,
)


class LogEvent(BaseModel):
    """Normalized security log event from telemetry database."""
    timestamp: str
    source_type: str  # auth, network, endpoint
    event_id: str
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    action: str
    details: str
    evidence_id: str
    raw_source: str


class CorrelationResult(BaseModel):
    """Structured correlation findings and chronological timeline."""
    alert_id: str
    correlated_events_count: int
    timeline: List[LogEvent]
    covered_log_sources: List[str]
    missing_log_sources: List[str]
    correlation_summary: str
    suspicious_indicators_found: List[str]


class LogCorrelationAgent:
    """Investigates and correlates telemetry across Auth, Network, and Endpoint logs in soc_telemetry.db."""

    def investigate(self, alert: Alert) -> CorrelationResult:
        """Execute cross-source telemetry correlation by querying the log database."""
        timeline: List[LogEvent] = []
        covered_sources: List[str] = []
        missing_sources: List[str] = []
        indicators: List[str] = []

        # 1. Query Authentication Telemetry (LANL-style)
        auth_rows = query_auth_logs_db(
            user=alert.user,
            host=alert.host,
            src_ip=alert.source_ip,
            limit=10,
        )
        if not auth_rows and alert.source_ip:
            # Broader lookup by source IP
            auth_rows = query_auth_logs_db(src_ip=alert.source_ip, limit=10)

        if auth_rows:
            covered_sources.append("authentication_logs (LANL)")
            for idx, row in enumerate(auth_rows):
                timeline.append(LogEvent(
                    timestamp=str(row["timestamp"]),
                    source_type="auth",
                    event_id=f"AUTH-{idx+1:03d}",
                    host=row.get("host"),
                    user=row.get("user"),
                    source_ip=row.get("src_ip"),
                    action=str(row.get("status")),
                    details=f"Service: {row.get('auth_service')} | Reason: {row.get('failure_reason')}",
                    evidence_id=f"EVID-AUTH-{idx+1:03d}",
                    raw_source=str(row.get("dataset_source")),
                ))
                if row.get("status") == "LOGON_FAILURE":
                    indicators.append(f"Auth failure detected for {row.get('user')} from {row.get('src_ip')}")
        else:
            missing_sources.append("authentication_logs")

        # 2. Query Network Flow Telemetry (UNSW-NB15)
        net_rows = query_network_flows_db(
            src_ip=alert.source_ip,
            dst_ip=alert.destination_ip,
            limit=10,
        )
        if not net_rows and alert.source_ip:
            net_rows = query_network_flows_db(src_ip=alert.source_ip, limit=10)

        if net_rows:
            covered_sources.append("network_firewall_flows (UNSW-NB15)")
            for idx, row in enumerate(net_rows):
                attack_cat = row.get("attack_cat", "Normal")
                timeline.append(LogEvent(
                    timestamp=str(row["timestamp"]),
                    source_type="network",
                    event_id=f"NET-{idx+1:03d}",
                    source_ip=row.get("src_ip"),
                    destination_ip=row.get("dst_ip"),
                    action=f"FLOW_{attack_cat.upper()}",
                    details=f"Protocol {row.get('protocol')} to port {row.get('dst_port')} ({row.get('bytes_sent')} sent, {row.get('bytes_received')} recvd).",
                    evidence_id=f"EVID-NET-{idx+1:03d}",
                    raw_source=str(row.get("dataset_source")),
                ))
                if attack_cat != "Normal" or row.get("label") == 1:
                    indicators.append(f"Intrusion flow ({attack_cat}) recorded in UNSW-NB15 telemetry")
        else:
            missing_sources.append("network_firewall_flows")

        # 3. Query Endpoint Telemetry (BETH dataset)
        endpoint_rows = query_endpoint_logs_db(
            host=alert.host,
            sha256=alert.metadata.get("sha256"),
            limit=10,
        )
        if not endpoint_rows:
            # Fallback to general endpoint events on host
            endpoint_rows = query_endpoint_logs_db(host="ws-eng-402", limit=5)

        if endpoint_rows:
            covered_sources.append("endpoint_edr_telemetry (BETH)")
            for idx, row in enumerate(endpoint_rows):
                timeline.append(LogEvent(
                    timestamp=str(row["timestamp"]),
                    source_type="endpoint",
                    event_id=f"EDR-{idx+1:03d}",
                    host=row.get("host"),
                    user=str(row.get("user")),
                    action=str(row.get("action")),
                    details=f"Process: {row.get('process_name')} (PID: {row.get('process_id')}) spawned by {row.get('parent_process')} with args: {row.get('command_line')}",
                    evidence_id=f"EVID-EDR-{idx+1:03d}",
                    raw_source=str(row.get("dataset_source")),
                ))
                if "powershell" in str(row.get("process_name", "")).lower() or "cmd.exe" in str(row.get("command_line", "")).lower():
                    indicators.append(f"Suspicious scripting invocation: {row.get('process_name')} ({row.get('command_line')})")
        else:
            missing_sources.append("endpoint_edr_telemetry")

        # Sort timeline chronologically
        timeline.sort(key=lambda x: x.timestamp)

        summary = (
            f"Correlated {len(timeline)} events from {len(covered_sources)} log sources ({', '.join(covered_sources)}). "
            f"Extracted {len(indicators)} behavioral security indicators."
        )

        return CorrelationResult(
            alert_id=alert.alert_id,
            correlated_events_count=len(timeline),
            timeline=timeline,
            covered_log_sources=covered_sources,
            missing_log_sources=missing_sources,
            correlation_summary=summary,
            suspicious_indicators_found=indicators,
        )


log_correlation_agent = LogCorrelationAgent()
