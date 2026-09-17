## Multi-Agent SOC Analyst: Autonomous Alert Triage & Investigation System

| Project Title | Multi-Agent SOC Analyst: An Agentic AI System for Autonomous Security Alert Triage, Investigation, and Reporting |
| --- | --- |
| Domain | Agentic AI, Security Operations (SOC), Applied ML / LLM Orchestration |
| Recommended Team Size | 4-5 students |
| Duration | 12 months (Semester 7 + Semester 8) |
| Credit Structure | 3 credits (Semester 7) + 12 credits (Semester 8) = 15 credits total, spanning one academic year |

## 1. Introduction & Motivation

Security Operations Centers (SOCs) are overwhelmed by alert volume. Analysts routinely triage hundreds to thousands of alerts a day, most of which are false positives, while genuine incidents require slow, manual cross- referencing across firewall logs, authentication logs, endpoint telemetry, and threat-intelligence feeds. Recent industry direction (e.g., multi-agent SOC platforms from major security vendors) shows a decisive shift toward collaborating specialist AI agents — rather than a single chatbot — that together triage, investigate, and report on alerts the way a human analyst team would. This project builds a scaled-down but functionally complete version of such a system, giving students hands-on exposure to agent orchestration, tool-calling, log analysis, and applied cybersecurity workflows.

## 2. Problem Statement

Design and build a multi-agent system that ingests raw security alerts (from a SIEM or synthetic alert feed), autonomously investigates each alert by querying relevant log sources and threat-intelligence sources, correlates findings across data sources, and produces a structured, human-readable incident report with a recommended severity and response action — reducing analyst triage time while maintaining a human-in-the- loop for final action approval.

## 3. Objectives

- Design a multi-agent architecture with clearly separated roles: Triage Agent, Log-Correlation Agent, Threat-Intelligence Agent, and Report-Generation Agent.

- Implement inter-agent orchestration (planner/coordinator pattern) so agents can call tools, share intermediate findings, and hand off tasks.

- Integrate with realistic log sources (firewall, authentication, endpoint/EDR-style logs) using open datasets or a simulated log generator.

- Build IOC (Indicator of Compromise) extraction and enrichment via public threat-intel feeds (e.g., AbuseIPDB, VirusTotal community API, MITRE ATT&CK mapping).

- Generate structured investigation reports (timeline, affected assets, severity, recommended action) instead of raw data dumps.


- Implement a human-in-the-loop approval gate before any automated response action (e.g., isolate host, block IP) is simulated/executed.

- Evaluate the system against a labelled alert dataset for triage accuracy, investigation quality, and time saved versus manual baseline.

## 4. Literature Survey / Related Work (indicative areas to review)

- Agentic AI architectures for cybersecurity (multi-agent LLM orchestration, planner-executor patterns).

- SOC automation and SOAR (Security Orchestration, Automation and Response) literature.

- MITRE ATT&CK framework and its use for alert classification / mapping.

- LLM tool-use / function-calling frameworks (LangGraph, CrewAI, AutoGen, or equivalent).

- Prior academic work on automated incident triage and alert-fatigue reduction.

## 5. Proposed System Architecture

The system is organized as a coordinator-led multi-agent pipeline:

- 1. Ingestion Layer: Receives alerts from a SIEM export, sample dataset, or a synthetic alert generator built by the team.

- 2. Triage Agent: Performs initial classification (true positive / false positive likelihood, alert category) and decides which downstream agents to invoke.

- 3. Log-Correlation Agent: Queries firewall, authentication, and endpoint logs relevant to the alert's IOCs (IP, user, host, hash) and builds an event timeline.

- 4. Threat-Intelligence Agent: Enriches IOCs using external/public threat-intel sources and maps behavior to MITRE ATT&CK techniques.

- 5. Report-Generation Agent: Synthesizes all findings into a structured incident report with severity scoring and a recommended response.

- 6. Human-in-the-Loop Gate: A reviewer dashboard where a human analyst approves, edits, or rejects the recommended action before it is (simulated) executed.

## 6. Methodology / Workflow

- 7. Literature review and requirement gathering; finalize alert taxonomy and severity scoring rubric.

- 8. Design agent roles, communication protocol, and orchestration graph.

- 9. Build/curate a synthetic or open-source log dataset with labelled ground-truth incidents.

- 10. Implement agents incrementally, starting with Triage and Log-Correlation.

- 11. Integrate threat-intelligence enrichment and MITRE ATT&CK mapping.

- 12. Build the report-generation agent and human-review dashboard.

- 13. Evaluate end-to-end against baseline manual triage and refine.

## 7. Tools, Technologies & Datasets

Category

Tools / Technologies / Datasets


| Agent Orchestration | LangGraph / CrewAI / AutoGen / custom orchestrator using an LLM API (Claude/GPT) with function-calling |
| --- | --- |
| Backend | Python (FastAPI) for agent services and tool endpoints |
| Log & SIEM Data | Public datasets — CICIDS2017/2018, UNSW-NB15, LANL Cyber log dataset, or a Splunk/Elastic sandbox with synthetic logs |
| Threat Intelligence | AbuseIPDB, VirusTotal (community tier), MITRE ATT&CK STIX data, AlienVault OTX |
| Storage | PostgreSQL / Elasticsearch for log indexing and querying |
| Dashboard/UI | React or Streamlit for the human-review interface |
| Evaluation | Labelled incident subsets from the chosen dataset for precision/recall benchmarking |

## 8. Semester-Wise Work Plan

| Phase | Deliverables / Activities | Weeks |
| --- | --- | --- |
|   | SEMESTER 7 — 3 CREDITS (Design, Literature Review & Proof-of-Concept) |   |
| Weeks 1–3 | Literature survey, problem finalization, requirement specification document. | 3 |
| Weeks 4–6 | System architecture design, agent role definitions, orchestration protocol, dataset shortlisting. | 3 |
| Weeks 7–10 | Proof-of-concept: single-agent (Triage Agent) working on a small labelled alert subset. | 4 |
| Weeks 11–13 | Sem-1 report, PoC demo, and internal review / mid-term evaluation. | 3 |
|   | SEMESTER 8 — 12 CREDITS (Full Implementation, Evaluation & Deployment) |   |
| Weeks 1–3 | Implement Log-Correlation Agent and integrate with log datasets. | 3 |
| Weeks 4–6 | Implement Threat-Intelligence Agent and MITRE ATT&CK mapping. | 3 |
| Weeks 7–9 | Implement Report-Generation Agent and human-review dashboard. | 3 |
| Weeks 10–12 | Full pipeline integration; end-to-end testing on the complete dataset. | 3 |
| Weeks 13–15 | Evaluation, benchmarking against manual baseline, performance tuning. | 3 |
| Weeks 16–18 | Final report, documentation, demo video, and viva-voce preparation. | 3 |

## 9. Evaluation Metrics

| Metric | What It Measures |
| --- | --- |
| Triage Accuracy | Precision/recall of true-positive vs false-positive classification against labelled ground truth |


| Investigation Completeness | % of relevant IOCs and log sources correctly identified and correlated per alert |
| --- | --- |
| Report Quality | Human-rated clarity/usefulness of generated reports (rubric-based scoring by evaluators) |
| Time-to-Report | Average time from alert ingestion to final report, compared to manual analyst baseline |
| False Action Rate | Rate at which the system recommends an incorrect or unsafe automated response |

## 10. Expected Outcomes

- A working multi-agent prototype capable of triaging and investigating security alerts with minimal human intervention.

- A benchmark comparison against manual/rule-based triage demonstrating time and accuracy gains.

- A publishable technical report / potential conference paper on multi-agent SOC automation.

- A portfolio-grade project directly aligned with current industry hiring needs in AI-driven SOC automation.

## 11. Suggested References / Starting Points

- MITRE ATT&CK Framework — https://attack.mitre.org

- CICIDS2017/2018 Intrusion Detection Datasets — Canadian Institute for Cybersecurity

- Vendor documentation on agentic SOC platforms (e.g., Microsoft Security Copilot / Project Perception- style architectures) for design inspiration

- LangGraph / CrewAI / AutoGen official documentation for multi-agent orchestration patterns
