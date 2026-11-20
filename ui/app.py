"""Human-in-the-Loop SOC Analyst Review Dashboard (Streamlit).

Allows security analysts to review multi-agent investigation findings,
inspect chronological timelines across UNSW-NB15, LANL, and BETH telemetry,
and approve, edit, or reject proposed remediation actions before simulated execution.
"""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from backend.models.schemas import Alert
from backend.orchestration.graph import soc_orchestrator
from backend.services.hitl_simulator import ReviewDecision, hitl_service

st.set_page_config(
    page_title="Multi-Agent SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Multi-Agent SOC Analyst — Analyst Review Dashboard")
st.markdown(
    "Autonomous security alert triage, cross-source log correlation, threat intelligence, "
    "and human-in-the-loop remediation gate."
)

# Sidebar: System Telemetry Status
st.sidebar.header("Telemetry Database Status")
db_path = Path("locals/data/soc_telemetry.db")
if db_path.exists():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    n_net = cur.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0]
    n_auth = cur.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
    n_end = cur.execute("SELECT COUNT(*) FROM endpoint_logs").fetchone()[0]
    conn.close()
    st.sidebar.metric("Network Flows (UNSW-NB15)", f"{n_net:,}")
    st.sidebar.metric("Auth Telemetry (LANL)", f"{n_auth:,}")
    st.sidebar.metric("Endpoint Telemetry (BETH)", f"{n_end:,}")
else:
    st.sidebar.warning("soc_telemetry.db not found. Run dataset ingestion first.")

st.sidebar.markdown("---")
reviewer_id = st.sidebar.text_input("Current Analyst Identity", value="analyst_lead_01")

# Load sample alerts
benchmark_path = Path("locals/benchmarks/golden_soc_benchmark.json")
sample_alerts = []
if benchmark_path.exists():
    with open(benchmark_path, "r", encoding="utf-8") as f:
        sample_alerts = json.load(f)

# Main Tab Layout
tab_investigate, tab_pending, tab_audit = st.tabs([
    "🔍 Alert Investigation",
    "⏳ Pending Review Queue",
    "📜 Immutable Audit Trail",
])

with tab_investigate:
    st.subheader("1. Select or Submit Security Alert")
    col1, col2 = st.columns([2, 1])

    with col1:
        if sample_alerts:
            alert_titles = [f"{a['alert_id']} — {a['event_type']} ({a['description'][:60]}...)" for a in sample_alerts]
            selected_idx = st.selectbox("Choose Sample Alert from Golden Benchmark", range(len(sample_alerts)), format_func=lambda i: alert_titles[i])
            chosen_alert_dict = sample_alerts[selected_idx]
        else:
            chosen_alert_dict = {
                "alert_id": "AL-001",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "185.220.101.5",
                "destination_ip": "10.0.0.12",
                "user": "alice.smith",
                "host": "dc-01.corp",
                "event_type": "authentication_failure",
                "description": "Repeated failed SSH logins followed by successful login from hostile IP.",
                "failed_attempts": 20,
                "metadata": {"login_success_after_failures": True},
            }

        st.json(chosen_alert_dict, expanded=False)

    with col2:
        st.info("The Coordinator invokes Triage, Log Correlation (UNSW-NB15/BETH/LANL), Threat Intel (MITRE ATT&CK), and Report Generation.")
        run_btn = st.button("🚀 Run Multi-Agent Investigation", type="primary", use_container_width=True)

    if run_btn:
        with st.spinner("Multi-Agent Coordinator orchestrating specialist agents..."):
            alert_obj = Alert(**chosen_alert_dict)
            state = {
                "alert": alert_obj,
                "triage_finding": None,
                "correlation_finding": None,
                "threat_intel_finding": None,
                "incident_report": None,
                "system1_used": False,
                "status": "started",
                "errors": [],
            }
            res = soc_orchestrator.invoke(state)
            report = res.get("incident_report")
            if report:
                case_id = hitl_service.submit_for_review(report)
                st.session_state["active_report"] = report
                st.session_state["active_case_id"] = case_id
                st.success(f"Investigation complete! Queued for review under Case ID: `{case_id}`")

    if "active_report" in st.session_state:
        rep = st.session_state["active_report"]
        st.markdown("---")
        st.subheader("2. Investigation Findings & Incident Report")

        # Top Summary Badges
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Disposition", rep.disposition.upper())
        c2.metric("Severity", rep.severity.upper())
        c3.metric("Confidence Score", f"{rep.confidence_score * 100:.1f}%")
        c4.metric("Evidence Citations", len(rep.evidence_citations))

        st.markdown(f"**Executive Summary:** {rep.executive_summary}")

        # Columns: Timeline & MITRE Techniques
        col_time, col_ti = st.columns([3, 2])
        with col_time:
            st.markdown("#### Chronological Telemetry Timeline")
            for t_item in rep.timeline_summary:
                st.code(t_item, language="text")

        with col_ti:
            st.markdown("#### MITRE ATT&CK Mappings")
            for m in rep.mitre_techniques:
                st.info(m)
            st.markdown("#### External Hostile Entities")
            if rep.external_threat_indicators:
                for ext in rep.external_threat_indicators:
                    st.error(f"Hostile Public IOC: `{ext}`")
            else:
                st.caption("No public hostile external entities found.")

        # Human-in-the-Loop Approval Gate
        st.markdown("---")
        st.subheader("3. Human-in-the-Loop Remediation Approval Gate")
        st.markdown(
            "Analysts must authorize, modify, or reject any response actions before simulation. "
            "Zero automated changes occur without cryptographic authorization."
        )

        for idx, act in enumerate(rep.proposed_actions):
            with st.expander(f"Proposed Action #{idx+1}: {act.action_type.upper()} ({act.target_entity})", expanded=True):
                st.markdown(f"**Target:** `{act.target_entity}` | **Risk Level:** `{act.risk_level.upper()}`")
                st.markdown(f"**Rationale:** {act.rationale}")

                decision_choice = st.radio(
                    f"Action #{idx+1} Decision",
                    ["Approve", "Reject", "Modify"],
                    horizontal=True,
                    key=f"dec_{idx}",
                )
                notes = st.text_input("Reviewer Justification / Notes", key=f"notes_{idx}", value="Verified incident telemetry and confirmed containment action.")

                if st.button(f"Commit Decision for Action #{idx+1}", key=f"commit_{idx}"):
                    dec_type = "approved" if decision_choice == "Approve" else ("rejected" if decision_choice == "Reject" else "modified")
                    dec_obj = ReviewDecision(
                        case_id=st.session_state["active_case_id"],
                        action_index=idx,
                        decision=dec_type,
                        reviewer_id=reviewer_id,
                        reviewer_notes=notes,
                    )
                    audit = hitl_service.record_decision(dec_obj)
                    st.success(f"Decision recorded! Execution ID: `{audit.execution_id}` | Status: `{audit.status}`")
                    st.balloons()

with tab_pending:
    st.subheader("Pending Analyst Review Queue")
    if hitl_service.pending_reviews:
        for cid, r in hitl_service.pending_reviews.items():
            st.markdown(f"- **Case `{cid}`** — Alert `{r.alert_id}` | Disposition: `{r.disposition}` | Proposed Actions: {len(r.proposed_actions)}")
    else:
        st.info("No investigations currently pending review.")

with tab_audit:
    st.subheader("Immutable Simulation Audit Trail")
    audit_file = Path("locals/logs/audit_trail.jsonl")
    if audit_file.exists():
        records = []
        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        if records:
            st.dataframe(records, use_container_width=True)
        else:
            st.caption("Audit log is currently empty.")
    else:
        st.caption("Audit trail log file not yet created.")
