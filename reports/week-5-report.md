# Week 5 Report — Human-in-the-Loop Analyst Dashboard & Review Gate

## Objective
Implement Week 5 of the project plan: build a functional **Human-in-the-Loop (HITL) Analyst Review Dashboard** using Streamlit (`ui/app.py`), directly fulfilling the requirements in Section 5 & 7 of [docs/project-specification.md](file:///c:/amve/apps/cpp/projects/Multi-Agent-SOC-Analyst/docs/project-specification.md).

---

## 1. Streamlit Dashboard Architecture (`ui/app.py`)

The dashboard interfaces directly with the FastAPI/LangGraph backend and local telemetry database:

1. **System Telemetry Status Sidebar**:
   - Queries `locals/data/soc_telemetry.db` directly and displays real-time telemetry metrics:
     - Endpoint Telemetry (BETH): 763,144 events
     - Network Flows (UNSW-NB15 + CICIDS-2017): 275,341 flows
     - Auth Telemetry (LANL): 200,000 logs
     - Total: **1,238,485 indexed records**
   - Binds the current analyst's identity (`analyst_lead_01`) for audit trails.

2. **Interactive Alert Investigation Tab**:
   - Allows analysts to choose any incident from the Golden Benchmark dataset or submit custom alerts.
   - Triggers the LangGraph coordinator to orchestrate Triage $\rightarrow$ Log Correlation $\rightarrow$ Threat Intel $\rightarrow$ Report Generation.
   - Renders the executive summary, disposition, severity badges, confidence score, and evidence citation count.

3. **Multi-Source Evidence Inspection**:
   - **Chronological Telemetry Timeline**: Renders step-by-step events across Auth, Network, and Endpoint logs with immutable `evidence_id` anchors.
   - **MITRE ATT&CK Mappings**: Displays linked tactics, technique IDs (`T1110`, `T1046`, etc.), and detection guidance.
   - **Hostile External Entities**: Highlights malicious IPs and file hashes while preserving RFC1918 internal boundaries.

4. **Human-in-the-Loop Remediation Gate**:
   - Presents each proposed response action (`isolate_host`, `block_ip`, `reset_credentials`).
   - Requires explicit analyst selection: **Approve**, **Reject**, or **Modify**.
   - Requires reviewer justification notes before committing.

5. **Safe Simulator & Immutable Audit Trail Tab**:
   - Approved actions trigger the simulation adapter.
   - Generates a SHA-256 payload hash and records the execution to `locals/logs/audit_trail.jsonl`.
   - Real-time audit log viewer embedded in the dashboard.

---

## 2. Running the Dashboard

To launch the dashboard using `uv`:

```bash
uv run streamlit run ui/app.py
```

---

## Next Increment (Week 6)
End-to-end multi-agent integration and automated testing driven by a subagent (`flash_lite` / Gemini Low) to execute automated regression and pipeline stress-testing.
