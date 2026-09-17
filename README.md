# Multi-Agent SOC Analyst — Week 1

This repository is the Week 1 proof of concept for the semester-long Multi-Agent SOC Analyst project.

> Day-1 proof-of-concept implementing alert ingestion and structured triage. Other agents will be added incrementally.

The current flow is deliberately small and deterministic:

```text
Alert -> validate -> Triage Agent -> structured TriageResult
```

It includes a rules baseline for brute-force login, port scan, suspicious outbound connection, malware/hash, benign activity, and unknown alerts. No automated response action is implemented.

## Repository layout

```text
├── docs/
│   └── project-specification.md  # Semester-long requirements
├── plans/
│   └── week-1-plan.md            # Current implementation plan
├── reports/
│   └── week-1-report.md          # Completed work and verification
├── backend/
│   ├── agents/triage.py          # Deterministic rules and LLM boundary
│   ├── models/schemas.py         # Alert and TriageResult models
│   ├── services/triage_service.py
│   ├── config.py
│   └── main.py                   # FastAPI application
├── data/alerts.json              # 12 synthetic labelled alerts
└── tests/                        # Unit and API tests
```

Project documents are grouped by purpose: requirements live in `docs/`, active plans in `plans/`, and completed implementation records in `reports/`.

## Setup

Python 3.11+ is recommended.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The app defaults to rules mode and needs no secrets. To configure it explicitly, copy `.env.example` to `.env`.

## Run the API

```bash
uvicorn backend.main:app --reload
```

Interactive API documentation is available at <http://127.0.0.1:8000/docs>.

Health check:

```bash
curl http://127.0.0.1:8000/health
```

PowerShell triage request:

```powershell
$body = @{
  alert_id = "A001"
  timestamp = "2026-09-17T14:20:00Z"
  source_ip = "185.10.20.30"
  destination_ip = "10.0.0.23"
  user = "alice"
  host = "host-23"
  event_type = "authentication"
  description = "20 failed SSH attempts followed by successful login"
  failed_attempts = 20
  metadata = @{ login_success_after_failures = $true }
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/alerts/triage `
  -ContentType "application/json" -Body $body
```

## Run tests

```bash
pytest
```

## Design boundaries

- Rules mode is the reliable baseline for Week 1 and remains available without an API key.
- The optional LLM adapter is a safe extension point only; no SDK, network call, or secret is required today.
- IOC extraction copies known structured values: IPs, host, user, and common hash fields.
- The API validates input and output with Pydantic.
- There is no database, frontend, threat-intelligence lookup, MITRE ATT&CK integration, orchestration framework, or automated remediation yet.

The intended later pipeline is:

```text
Alert -> Triage -> Log Correlation -> Threat Intel -> MITRE -> Report -> Human Approval
```
