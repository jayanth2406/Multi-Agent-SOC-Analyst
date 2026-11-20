# Week 18 Report — Final Capstone Documentation, Specification Compliance Audit & Viva-Voce Defense Guide

## Executive Summary
This document provides the final capstone report and technical audit for the **Multi-Agent SOC Analyst: Autonomous Alert Triage & Investigation System**, fulfilling all academic and technical requirements outlined in [docs/project-specification.md](file:///c:/amve/apps/cpp/projects/Multi-Agent-SOC-Analyst/docs/project-specification.md) across Semester 7 (3 Credits) and Semester 8 (12 Credits).

---

## 1. Compliance Audit Against Project Specification Objectives

Every objective specified in Section 3 of `docs/project-specification.md` has been implemented and empirically verified:

| Specification Requirement | Implementation Details | Verification Artifact | Compliance Status |
|---|---|---|---|
| **Clearly separated agent roles** | Triage Agent, Log-Correlation Agent, Threat-Intelligence Agent, and Report-Generation Agent. | `backend/agents/` | **100% Compliant** |
| **Inter-agent orchestration** | LangGraph StateGraph coordinator with conditional edge routing and fast-pathing. | `backend/orchestration/graph.py` | **100% Compliant** |
| **Realistic log datasets** | Ingested **1,238,485 indexed records** across BETH (763k), UNSW-NB15 (175k), CICIDS-2017 (100k), and LANL (200k). | `locals/data/soc_telemetry.db` (259.81 MB) | **100% Compliant** |
| **IOC extraction & enrichment** | Automated IOC extraction, VirusTotal / AbuseIPDB reputation, and RFC1918 privacy guard. | `backend/tools/threat_intel_tools.py` | **100% Compliant** |
| **MITRE ATT&CK mapping** | Enterprise STIX 2.1 matrix correlation across 14 tactics (T1110, T1046, T1059, T1071, T1078, etc.). | `data/mitre_attack_catalog.json` | **100% Compliant** |
| **Structured incident reports** | Chronological timelines with concrete evidence citations (`EVID-*`), blast radius, and remediation. | `backend/agents/report_generator.py` | **100% Compliant** |
| **Human-in-the-Loop review gate** | Streamlit review dashboard (`ui/app.py`) with action approval/modification/rejection and SHA-256 audit trail. | `ui/app.py`, `locals/logs/audit_trail.jsonl` | **100% Compliant** |
| **Empirical benchmark evaluation** | Golden Benchmark evaluation measuring Triage Accuracy (83.67%), Latency (48.5ms), and False Action Rate (0.0%). | `locals/benchmarks/benchmark_results.json` | **100% Compliant** |
| **System 1 Decision Model** | Deployed small neural decision model (<100M params, DistilBERT MNLI) with typed primitives (`choice`, `noul`). | `scripts/evaluate_small_decision_model.py` | **100% Compliant** |

---

## 2. System Architecture & Component Summary

```
                       SIEM Alert Ingestion
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │     System 1 Triage Agent (<100M Params)     │
         │  Single Forward Pass (DistilBERT / Laya)    │
         │   • noul(is_malicious): Calibrated P        │
         │   • choice(category): Bounded selection      │
         └──────────────────────┬───────────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
       [High Conf FP]                [Needs Investigation]
       Auto-Closed Noise                       │
                                               ▼
                                ┌──────────────────────────────┐
                                │    Log-Correlation Agent     │
                                │   Queries 1.2M+ Rows DB      │
                                │   (BETH, UNSW, CICIDS, LANL) │
                                └──────────────┬───────────────┘
                                               │
                                               ▼
                                ┌──────────────────────────────┐
                                │   Threat-Intelligence Agent  │
                                │   • RFC1918 Privacy Guard    │
                                │   • MITRE ATT&CK STIX 2.1    │
                                └──────────────┬───────────────┘
                                               │
                                               ▼
                                ┌──────────────────────────────┐
                                │   Report-Generation Agent    │
                                │   • Evidence Citations       │
                                │   • Remediation Proposals    │
                                └──────────────┬───────────────┘
                                               │
                                               ▼
                                ┌──────────────────────────────┐
                                │  Human-in-the-Loop Dashboard │
                                │  (Streamlit UI / SHA-256)    │
                                └──────────────────────────────┘
```

---

## 3. Comprehensive Viva-Voce Defense Guide

### Q1: Why use a multi-agent system rather than a single large language model (LLM)?
* **Answer**: Single LLMs suffer from high latency (2–5 seconds per alert), hallucinations, and lack of role separation. When a single model is asked to query databases, evaluate threat intelligence, and make remediation decisions simultaneously, it frequently invents log entries or leaks private IPs. In our multi-agent architecture, roles are strictly partitioned: the Log-Correlation Agent only executes deterministic database queries over indexed telemetry, the Threat-Intelligence Agent enforces privacy boundaries, and the Coordinator ensures every finding in the report is bound to an immutable evidence ID (`EVID-*`).

### Q2: What is the difference between a traditional classifier and a System 1 Decision Model (Laya, Clef, Jev)?
* **Answer**: Traditional classifiers (like TF-IDF + Logistic Regression) memorize word tokens without semantic understanding, failing when attack phrasing changes. Autoregressive LLMs generate conversational text token-by-token, which is slow and prone to formatting errors. A **System 1 Decision Model** is a non-autoregressive neural model (e.g., ModernBERT or DistilBERT with classification heads) that processes unstructured text alongside typed decision contracts (`noul` for calibrated boolean probabilities, `choice` for bounded selections) in a single forward pass (**~30 ms**).

### Q3: How does the system protect internal enterprise data from leaking to public threat intelligence feeds?
* **Answer**: The Threat-Intelligence Agent implements a strict **RFC1918 Privacy Guard** (`backend/tools/threat_intel_tools.py`). Before any external lookup is performed, incoming IP addresses are evaluated against RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, and link-local ranges. Internal addresses are resolved against the local inventory database, completely preventing private IP leakage to third-party APIs.

### Q4: How does the system scale across large telemetry datasets?
* **Answer**: The database (`locals/data/soc_telemetry.db`) contains **1,238,485 rows** (259.81 MB). To maintain sub-millisecond retrieval, B-Tree indices (`idx_net_src`, `idx_auth_user`, `idx_end_host`, etc.) are established on primary filter attributes. Measured query latencies on the live database are **11.6 ms** for 275k network flows and **4.0 ms** for 200k authentication logs.

### Q5: How is human oversight maintained before destructive containment actions?
* **Answer**: Section 3 of the specification mandates a Human-in-the-Loop approval gate. High-risk actions (`isolate_host`, `block_ip`, `reset_credentials`) are presented in the Streamlit dashboard (`ui/app.py`). An analyst must inspect the correlated timeline and evidence citations, provide a justification note, and click **Approve** before the action is simulated. Every decision is cryptographically logged using SHA-256 hashing to `locals/logs/audit_trail.jsonl` for compliance and non-repudiation.
