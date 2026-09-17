# Week 1 Report — Multi-Agent SOC Analyst

## Outcome

Week 1 now contains a runnable, testable backend proof of concept for the first project slice:

```text
security alert -> Pydantic validation -> deterministic triage -> structured result
```

The implementation stops at triage as required. It does not make response changes, call external threat-intelligence services, or pretend that future agents already exist.

## What was implemented and why

### 1. Repository foundation

The repository was organized around the requested future growth path while keeping the current code small:

- `backend/` contains application code.
- `backend/models/` contains shared input/output contracts.
- `backend/agents/` contains agent logic.
- `backend/services/` keeps orchestration/use-case logic out of HTTP routes.
- `data/` contains reproducible synthetic alerts.
- `tests/` contains unit and API tests.
- `docs/` contains stable project requirements and reference material.
- `plans/` contains active implementation plans and checklists.
- `reports/` contains completed work reports and verification records.

This separation makes the deterministic rules easy to inspect and gives later log-correlation, threat-intelligence, reporting, and approval components clear homes.

### 2. Data contracts

`backend/models/schemas.py` defines:

- `Alert`: a validated, normalized alert with optional real-world fields and flexible metadata.
- `TriageResult`: a closed, structured response with constrained classification/severity values and confidence validation from `0.0` to `1.0`.

Pydantic validation ensures malformed requests receive a `422` response and that the API never returns arbitrary triage text in place of the agreed result shape.

### 3. Deterministic triage baseline

`backend/agents/triage.py` implements `DeterministicTriageAgent`. Its ordered rules cover:

- repeated failed authentication and successful login after failures -> `brute_force`;
- ordinary password typos -> likely false positive;
- many ports contacted quickly -> `port_scan`;
- approved administrative activity or known internal scanner -> likely false positive;
- suspicious outbound connections -> `suspicious_outbound_connection`;
- suspicious executable/hash or EDR alert -> `malware`;
- unmatched events -> `needs_investigation`.

Every branch returns the same `TriageResult` model, includes a short reasoning summary, lists relevant investigations, and recommends investigation rather than automatic remediation.

### 4. IOC preparation

`extract_iocs()` copies known values from the structured alert: source IP, destination IP, host, user, and common hash fields (`hash`, `file_hash`, `sha256`, `md5`). It de-duplicates values while preserving order. This creates the field future log-correlation and threat-intelligence agents will consume without introducing fragile NLP extraction in Week 1.

### 5. Safe optional LLM boundary

`backend/config.py` reads `TRIAGE_MODE`, `LLM_API_KEY`, and `LLM_MODEL` from environment configuration. `OptionalLLMTriageAdapter` documents the provider integration point but intentionally has no SDK or network dependency yet.

`TriageService` tries the optional adapter only when explicitly configured and falls back to deterministic rules if the adapter is unavailable or fails. Therefore the repository works with no secret and the baseline remains usable for evaluation.

### 6. FastAPI endpoints

`backend/main.py` exposes:

- `GET /health` -> `{"status": "ok"}`
- `POST /alerts/triage` -> validated `TriageResult`

The route only handles HTTP concerns. Triage selection and fallback behavior live in `TriageService`.

### 7. Synthetic data

`data/alerts.json` contains 12 labelled examples across brute-force login, port scanning, suspicious outbound connections, malware/hash alerts, benign typos, approved administration, and unknown events. The examples are intentionally small and readable so the rules can be inspected against them before a larger dataset is selected.

### 8. Verification

`tests/test_triage.py` checks the classification rules, severity escalation, benign behavior, unknown handling, confidence bounds, and IOC extraction.

`tests/test_api.py` checks the health endpoint, valid triage response shape, validation errors, and operation without an LLM API key.

The final verification command is:

```bash
pytest
```

Verified in this workspace:

- `12 passed` with pytest.
- All 12 JSON alerts parse successfully and produce confidence values within `0.0` to `1.0`.
- A live Uvicorn smoke test returned `200` from both `/health` and `/alerts/triage`.
- The service returned the expected `brute_force`/`high` result for the sample successful-login-after-failures alert.

## File and folder guide

| Path | Contents | Why it exists |
| --- | --- | --- |
| `backend/main.py` | FastAPI app and two endpoints | HTTP entry point |
| `backend/config.py` | Environment-backed settings | Keeps configuration and secrets out of code |
| `backend/agents/triage.py` | Rules engine, IOC extraction, LLM boundary | Implements the Week 1 agent behavior |
| `backend/models/schemas.py` | `Alert` and `TriageResult` | Shared validated contracts |
| `backend/services/triage_service.py` | Agent selection and fallback | Keeps business logic out of routes |
| `data/alerts.json` | 12 synthetic labelled alerts | Reproducible demo/evaluation inputs |
| `tests/test_triage.py` | Unit tests | Protects rule behavior |
| `tests/test_api.py` | FastAPI integration tests | Protects HTTP behavior and validation |
| `.env.example` | Safe configuration template | Shows optional settings without secrets |
| `.gitignore` | Local/cache/secret exclusions | Prevents accidental commits of environment files |
| `requirements.txt` | Minimal runtime/test dependencies | Reproducible setup |
| `README.md` | Setup, run, API, and scope instructions | Makes the project easy to run and demo |
| `docs/project-specification.md` | Semester-long project requirements | Stable source of project scope and future phases |
| `plans/week-1-plan.md` | Week 1 scope and acceptance checklist | Keeps implementation aligned with the project plan |
| `reports/week-1-report.md` | This implementation report | Records what was built and the reasoning |

## Deliberately deferred

The following are outside the Week 1 acceptance boundary: LangGraph/CrewAI/AutoGen, multi-agent orchestration, PostgreSQL/Elasticsearch, external threat-intelligence APIs, MITRE ATT&CK integration, frontend/dashboard work, automated response actions, and full incident reports. They remain future increments in the semester plan.
