# Multi-Agent SOC Analyst — Requirements Specification

Nov 24, 2026

This specification starts with the alert taxonomy and severity rubric, because they decide which alerts exist, how bad each is, and how deeply each is investigated. Functional and non-functional requirements follow.

## Alert taxonomy

The system recognises 10 categories: 7 attack categories, 2 benign categories and 1 catch-all. Each is anchored to a MITRE ATT&CK tactic, to the community [Reference Security Incident Taxonomy](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force) (RSIT) used by European CSIRTs, and to labels that already exist in the chosen datasets. This means ground truth comes from the data, not from the team.

| Code | Category | Covers | ATT&CK tactic and example techniques | RSIT class | Dataset labels that map here |
| --- | --- | --- | --- | --- | --- |
| C1 | Reconnaissance | Port and service scans, host sweeps | Reconnaissance, Discovery: T1595, T1046 | Information Gathering: Scanning | UNSW Reconnaissance, Analysis; CICIDS PortScan |
| C2 | Credential attack | Brute force, password spraying, failure bursts | Credential Access: T1110 | Intrusion Attempts: Login attempts | CICIDS FTP-/SSH-Patator; LANL failed logons |
| C3 | Account compromise and lateral movement | Success after failures, unusual logons, remote-service hops | Initial Access, Lateral Movement: T1078, T1021 | Intrusions: account compromise | LANL red-team events |
| C4 | Exploitation | Exploits, shellcode, web attacks (SQLi, XSS) | Initial Access, Execution: T1190, T1203 | Intrusion Attempts: exploitation of known vulnerabilities | UNSW Exploits, Shellcode, Fuzzers, Generic; CICIDS Web Attack, Heartbleed, Infiltration |
| C5 | Malware and malicious execution | Backdoors, worms, malicious processes, abused system tools | Execution, Persistence: T1059, T1204 | Malicious Code: infected system | UNSW Backdoors, Worms; BETH evil and sus |
| C6 | Command and control, exfiltration | Beaconing, bot traffic, DNS tunnelling, large outbound transfers | Command and Control, Exfiltration: T1071, T1041, T1048 | Malicious Code: C2 | CICIDS Botnet |
| C7 | Denial of service | Floods, resource exhaustion | Impact: T1498, T1499 | Availability: DoS / DDoS | UNSW DoS; CICIDS DoS, DDoS |
| B1 | Authorised activity | Approved scanners, admin work, backups, patching | — | — | Scripted benign cases |
| B2 | User error | Password typos, mistyped URLs | — | — | Scripted benign cases; LANL isolated failures |
| U0 | Unclassified | Anything that fits no category with enough confidence | — | Other: Undetermined | — |

**Rules for applying it:**

- Each alert gets **one primary category**. The report may list secondary categories when the story spans several, such as C2 leading to C3.
- Triage assigns a **provisional** category. Investigation may change it; for example, a C2 brute-force alert becomes C3 once a successful logon is found. The report records both.
- U0 is not a failure state. It routes the alert to full investigation and tells the analyst the system was unsure.

## Disposition labels

Category says *what kind* of activity it is; disposition says *whether it is a real threat*. They are separate fields, because the same category can be any disposition: a port scan can be an attacker (true positive) or the approved Nessus scanner (benign true positive).

| Disposition | Meaning | Example | Who can assign it |
| --- | --- | --- | --- |
| True positive (TP) | Real malicious activity | Brute force from a known-bad IP | Triage (provisional), Report (final) |
| Benign true positive (BTP) | The detection was correct, but the activity is authorised | Approved vulnerability scan raises a port-scan alert | Triage, Report |
| False positive (FP) | The detection itself was wrong; nothing of the kind happened | A DNS rule fires on a normal software update domain | Triage, Report |
| Needs investigation | Not enough evidence to decide | U0 alerts; any case with major coverage gaps | Triage only; the Report must resolve it or mark it **inconclusive** |

Triage accuracy is reported separately for TP, BTP and FP, with the two-class split alongside it: **threat** (TP) vs **not a threat** (BTP + FP). Reporting BTP on its own shows whether the system recognises approved scanners and admins, which a single false-positive figure would hide.

## Severity rubric

Severity answers "how bad is this if it is real?" It is read from a table of two factors, **attack stage** and **asset criticality**, then adjusted by at most one level. How sure the system is gets reported separately as **confidence**, so an uncertain alert is never quietly scored as minor.

The two factors follow the prioritisation logic of NIST SP 800-61r2, which ranks incidents by functional impact, information impact and recoverability ([CISA guidelines](https://www.cisa.gov/sites/default/files/2023-01/Federal_Incident_Notification_Guidelines.pdf)). Stage stands in for how far the attacker got; criticality stands in for what is at stake.

### Factor 1: attack stage

| Stage | Meaning | Typical categories |
| --- | --- | --- |
| 0 — None | Not a threat (disposition BTP or FP) | B1, B2 |
| 1 — Attempt | Tried, no sign of success | C1; C2 with no success; C4 blocked |
| 2 — Disruption or partial success | Service degraded, or payload delivered but execution not confirmed | C7; C4 delivered |
| 3 — Compromise | Attacker has access or code running | C2 with success, C3, C4 succeeded, C5 |
| 4 — Post-compromise | Attacker is spreading, talking out or taking data | C3 lateral movement, C6 |

### Factor 2: asset criticality

Read from the asset inventory, so it is known at triage time. When several assets are involved, the most critical one counts.

| Tier | Examples |
| --- | --- |
| Low | Lab and test machines, guest network |
| Standard | User workstations, standard user accounts |
| High | Production servers, service accounts |
| Critical | Domain controllers, production databases, admin accounts, security tooling |

### Severity table

Stage 0 is always **Informational**. Otherwise:

| Stage ↓ / Asset → | Low | Standard | High | Critical |
| --- | --- | --- | --- | --- |
| 1 — Attempt | Low | Low | Low | Medium |
| 2 — Disruption / partial | Low | Medium | Medium | High |
| 3 — Compromise | Medium | High | High | Critical |
| 4 — Post-compromise | High | High | Critical | Critical |

### From category to severity

A category does not have a fixed severity. It sets which **stages** are possible, and the asset tier then picks the level from the table above. The same category can therefore land on different levels.

| Category | Possible stages | Severity range before modifiers |
| --- | --- | --- |
| C1 Reconnaissance | 1 | Low (Medium on a critical asset) |
| C2 Credential attack | 1; becomes C3 once a logon succeeds | Low (Medium on a critical asset) |
| C3 Account compromise, lateral movement | 3, or 4 when spreading | Medium to Critical |
| C4 Exploitation | 1 if blocked, 2 if delivered, 3 if it succeeded | Low to Critical |
| C5 Malware, malicious execution | 3 | Medium to Critical |
| C6 Command and control, exfiltration | 4 | High to Critical |
| C7 Denial of service | 2 | Low to High |
| B1, B2 Benign | 0 | Informational |
| U0 Unclassified | Treated as 2 until evidence says otherwise | Provisional only; always full investigation |

Modifiers can raise any of these by one level.

### Modifiers

Add **one level** (never above Critical, never more than one in total) if either holds:

- **Spread:** more than one host or account is affected.
- **Ongoing:** the activity is still happening when the report is written.

There are no downward modifiers. The only way down is a change of disposition to BTP or FP, which makes the alert Informational.

### Confidence

A number from 0 to 1, shown next to severity. It rises with threat-intel confirmation and with corroboration from more than one log source, and falls with coverage gaps. It never changes the severity level; it decides how much investigation is needed (next section).

## Severity levels and investigation depth

Not every alert gets a full investigation. Informational and Low alerts get a **light** investigation unless a safeguard fires; Medium, High and Critical always get the **full** one.

| Level | What it means | Investigation | Default proposed action |
| --- | --- | --- | --- |
| Informational | Not a threat (BTP or FP) | Light | `close_benign` |
| Low | An attempt against a low-value or ordinary asset | Light | `escalate_tier2`, or `block_ip` when the source is external and threat intel confirms it is malicious |
| Medium | An attempt on a critical asset, or a partial success | Full | Depends on category |
| High | Compromise of an ordinary asset, or disruption of a critical one | Full | Containment actions for analyst approval |
| Critical | Compromise of a critical asset, or an attacker spreading on high-value systems | Full; top of the queue | Containment actions for analyst approval |

**Light investigation** means triage, an asset-inventory lookup, a threat-intel check on public IOCs, and a short report. **Full investigation** adds log correlation across all relevant sources, ATT&CK mapping and the extra rounds described in the architecture. Every alert, light or full, still reaches the analyst queue.

### Safeguards that upgrade a light investigation to full

1. Any public IOC comes back malicious from threat intel.
2. The asset is High or Critical tier.
3. The category is U0 (unclassified).
4. Triage confidence is below a threshold **calibrated on the validation set**, not picked by hand.
5. The same source IP or account has appeared in at least N alerts in the last 24 hours, where N is also calibrated. Many small alerts from one source can be one bigger attack.

### Provisional vs final severity

Severity is computed twice. Triage computes a **provisional** severity from the estimated stage and the inventory's asset tier, and that decides light or full. The Report agent computes the **final** severity from the evidence. If a light investigation finds a higher stage than triage estimated, the run switches to full. The report shows both values, so the team can measure how often triage under- or over-estimates.

## Worked examples

Five sample alerts, scored with the rubric above, show the range from Informational to Critical.

| # | Alert | Category | Disposition | Stage | Asset tier | Table → modifier → severity | Investigation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Approved Nessus scanner sweeps the dev subnet | C1 | BTP | 0 | — | Informational | Light |
| 2 | 40 failed SSH logins on a user workstation from a public IP; no success found | C2 | TP | 1 | Standard | Low → none → **Low** | Light, upgraded to full because threat intel flags the IP (safeguard 1) |
| 3 | DoS flood on the production web server, still running | C7 | TP | 2 | High | Medium → +1 ongoing → **High** | Full |
| 4 | Failed logins, then a successful logon to a domain admin account | C2 → C3 | TP | 3 | Critical | **Critical** (already at the top) | Full |
| 5 | Encoded PowerShell on two finance workstations, then regular beacons to an external IP | C5 → C6 | TP | 4 | Standard | High → +1 spread → **Critical** | Full |

Example 2 shows why safeguards matter: on stage and asset alone it is Low, but a known-bad source earns it the full investigation. Example 4 shows a category changing during investigation.

## Decisions

Four are decided and one is deferred.

| Question | Status | Answer |
| --- | --- | --- |
| Categories | Decided | Keep all 10 |
| Accuracy scoring | Decided | Report TP, BTP and FP separately, plus the two-class split |
| Asset inventory | Deferred | See **To be done** below |
| Medium alerts | Decided | Always full investigation |
| Modifiers | Decided | Spread and ongoing, capped at one level in total |

## Scope and users

The system triages and investigates security alerts and proposes responses; a human always makes the final call.

| User | What they need from the system |
| --- | --- |
| SOC analyst (Tier 1) | A ranked queue, clear reports with evidence, and a fast way to approve, change or reject actions |
| Senior analyst (Tier 2) | Escalated and inconclusive cases with the full trace of what each agent did |
| Evaluator (examiner, team) | Reproducible runs and the five metrics computed from logs |

**The system must:** ingest alerts, classify them with the taxonomy above, investigate them at the depth their severity requires, produce cited reports, and simulate approved actions.

**The system must not:** act on real infrastructure, send internal identifiers to outside services, or execute any action without a recorded human decision.

## Functional requirements

There are 40 requirements: 33 Must, 7 Should. The Sem 7 rows are the triage proof of concept; everything else is Semester 8, in the order the project plan sets. **Must** = the system fails without it; **Should** = expected, but can slip.

| ID | Requirement | Priority | When |
| --- | --- | --- | --- |
| **Ingestion** | | | |
| FR-ING-1 | Accept alerts over REST, one at a time or in batches | Must | Sem 7, wk 7–10 |
| FR-ING-2 | Reject malformed alerts with field-level errors | Must | Sem 7, wk 7–10 |
| FR-ING-3 | Normalise alert fields to the common schema and keep the raw alert | Must | Sem 7, wk 7–10 |
| FR-ING-4 | Replay a file of alerts at a set rate, for testing | Should | Sem 8, wk 10–12 |
| **Triage** | | | |
| FR-TRI-1 | Assign a provisional category from the 10-category taxonomy | Must | Sem 7, wk 7–10 |
| FR-TRI-2 | Assign a provisional disposition and a confidence from 0 to 1 | Must | Sem 7, wk 7–10 |
| FR-TRI-3 | Extract IOCs: IPs, domains, file hashes, users, hosts | Must | Sem 7, wk 7–10 |
| FR-TRI-4 | Compute provisional severity with the rubric, using the asset inventory | Must | Sem 7, wk 7–10 |
| FR-TRI-5 | Decide light or full investigation from severity and the five safeguards | Must | Sem 7, wk 7–10 |
| FR-TRI-6 | Give a short reasoning summary for every decision | Must | Sem 7, wk 7–10 |
| FR-TRI-7 | Work with no API key, using rules or a local model | Must | Sem 7, wk 7–10 |
| **Log correlation** | | | |
| FR-COR-1 | Query authentication, network and endpoint logs by IOC within a time window | Must | Sem 8, wk 1–3 |
| FR-COR-2 | Build an ordered timeline in which every event cites its evidence ID | Must | Sem 8, wk 1–3 |
| FR-COR-3 | Pivot once on a newly found entity, such as a second host | Should | Sem 8, wk 1–3 |
| FR-COR-4 | Report which log sources were covered and which were missing | Must | Sem 8, wk 1–3 |
| **Threat intelligence** | | | |
| FR-TI-1 | Filter out internal IPs, hosts, users and domains before any external call | Must | Sem 8, wk 4–6 |
| FR-TI-2 | Look up public IPs (AbuseIPDB, OTX) and file hashes (VirusTotal, OTX) | Must | Sem 8, wk 4–6 |
| FR-TI-3 | Support live, cache-only and replay modes | Must | Sem 8, wk 4–6 |
| FR-TI-4 | Respect provider rate limits and fall back to cache when a quota runs out | Must | Sem 8, wk 4–6 |
| FR-TI-5 | Map behaviour to ATT&CK techniques from the official STIX bundle, each with its evidence IDs | Must | Sem 8, wk 4–6 |
| **Report generation** | | | |
| FR-REP-1 | Produce a report with summary, category, disposition, final severity with its rubric breakdown, confidence, timeline, affected assets, external indicators, ATT&CK techniques, proposed actions and coverage gaps | Must | Sem 8, wk 7–9 |
| FR-REP-2 | Cite evidence for every factual statement; reject reports with uncited claims | Must | Sem 8, wk 7–9 |
| FR-REP-3 | Propose only actions from the category's playbook whose conditions hold | Must | Sem 8, wk 7–9 |
| FR-REP-4 | Show provisional and final severity side by side | Should | Sem 8, wk 7–9 |
| **Human review and actions** | | | |
| FR-HITL-1 | Queue every report, sorted by severity and then age | Must | Sem 8, wk 7–9 |
| FR-HITL-2 | Let the analyst approve, modify or reject each action, with a required reason | Must | Sem 8, wk 7–9 |
| FR-HITL-3 | Require the host name to be typed to confirm `isolate_host` | Should | Sem 8, wk 7–9 |
| FR-HITL-4 | Simulate approved actions only; never call a real system | Must | Sem 8, wk 7–9 |
| FR-HITL-5 | Keep a hash-chained audit log, with a check that finds any altered record | Must | Sem 8, wk 7–9 |
| FR-HITL-6 | Let the analyst flag a wrong disposition or severity, stored as feedback | Should | Sem 8, wk 7–9 |
| **Dashboard** | | | |
| FR-UI-1 | Provide queue, case, decision and audit-and-metrics views | Must | Sem 8, wk 7–9 |
| FR-UI-2 | Open the raw log row or threat-intel response behind any citation | Must | Sem 8, wk 7–9 |
| FR-UI-3 | Show the step-by-step trace of each run | Should | Sem 8, wk 7–9 |
| **Orchestration** | | | |
| FR-ORC-1 | Route light or full; run correlation and threat intel in parallel; allow up to 2 extra rounds within a 60 s budget | Must | Sem 8, wk 10–12 |
| FR-ORC-2 | Trace every step with inputs, outputs, tool calls and timings | Must | Sem 8, wk 10–12 |
| FR-ORC-3 | Retry a failed step once, log the failure, and continue the run | Must | Sem 8, wk 10–12 |
| **Evaluation** | | | |
| FR-EVAL-1 | Compute the five spec metrics from traces and labels with scripts | Must | Sem 8, wk 13–15 |
| FR-EVAL-2 | Run baselines: rules-only triage, a single-agent LLM and template-only reports | Must | Sem 8, wk 13–15 |
| FR-EVAL-3 | Run ablations with and without the LLM, threat intel and extra rounds | Should | Sem 8, wk 13–15 |
| FR-EVAL-4 | Report TP, BTP and FP results separately | Must | Sem 8, wk 13–15 |

## Non-functional requirements

Every quality target here is a number or a yes/no check, so each one can be tested. The latency figures are proposed starting points; revise them once the first end-to-end runs are timed.

| ID | Area | Requirement | How it is checked |
| --- | --- | --- | --- |
| NFR-PERF-1 | Performance | Triage takes 1 s or less per alert (median), without an LLM | Timing in the run trace |
| NFR-PERF-2 | Performance | Light investigations finish in 10 s or less (median); full investigations finish within the 60 s budget for 95% of alerts | Timing in the run trace |
| NFR-PERF-3 | Performance | Each log query returns in 200 ms or less on the full database | Query benchmark script |
| NFR-SAFE-1 | Safety | No action is ever executed without a recorded human decision | Automated test; audit-log check |
| NFR-SAFE-2 | Safety | No high-risk action is proposed for any B1 or B2 alert in the test set | False action rate script |
| NFR-PRIV-1 | Privacy | No internal IP, host, user or domain appears in any outbound request | Outbound-request log scanned in tests |
| NFR-PRIV-2 | Privacy | API keys live only in `.env` and are never committed | Secret scan in CI |
| NFR-REPRO-1 | Reproducibility | One command rebuilds the database from scratch with the same row counts and checksums | Rebuild twice and compare |
| NFR-REPRO-2 | Reproducibility | Re-running an evaluation in replay mode gives identical metrics | Run twice and compare; LLM responses are cached for evaluation runs |
| NFR-REL-1 | Reliability | The full pipeline runs offline with no API keys, at reduced quality | Test run with keys removed |
| NFR-REL-2 | Reliability | A missing log source or a failed provider never crashes a run | Fault-injection tests |
| NFR-EXPL-1 | Explainability | Every report shows each agent's reasoning summary and the severity breakdown (stage, tier, modifiers) | Report schema validation |
| NFR-USE-1 | Usability | An analyst can go from the queue to a recorded decision in 3 clicks or fewer | Walkthrough during the manual study |
| NFR-MAINT-1 | Maintainability | All tests pass on a fresh clone in CI; backend test coverage is 70% or more | CI run and coverage report |
| NFR-MAINT-2 | Maintainability | Any agent can switch between LLM and rules with a config setting, without touching the graph | Config test |
| NFR-COST-1 | Cost | Running costs are zero: free tiers only, and full evaluations use replay mode | Provider dashboards |

## Data requirements

Ground truth must come from the datasets' own labels or from documented scripts, and no alert may appear, word for word, in more than one split.

| ID | Requirement |
| --- | --- |
| DR-1 | Use UNSW-NB15, CICIDS2017, BETH and LANL auth data (or labelled synthetic auth logs if LANL is unavailable), each with a pinned version and checksum. |
| DR-2 | Every log row records its dataset, version, `is_synthetic`, `is_overlay` and its original label. Agents can never see the label. |
| DR-3 | Dataset values are never rewritten in place. Cross-source links exist only through the scenario overlay table. |
| DR-4 | Alerts come from three sources: labelled attack rows (TP), scripted authorised activity and user errors (BTP), and deliberately loose detection rules run over benign-labelled rows (FP). |
| DR-5 | Every alert has a ground-truth record: category, disposition, stage, final severity, expected IOCs, expected log sources and the set of acceptable actions. |
| DR-6 | Splits are made by source row and scenario. No alert description is shared across splits; a near-duplicate check runs before every evaluation. |
| DR-7 | Alert metadata contains no fields that give away the label, such as `approved_activity` or `ground_truth_*`. |
| DR-8 | Proposed sizes: a proof-of-concept set of about 200 alerts with at least 15 per category; a final test set of at least 500 alerts; and 12–20 overlay scenarios for measuring investigation completeness. |
| DR-9 | A threat-intel replay snapshot exists for every public IOC in the test set. |

The final test set comes in two mixes: a **balanced** mix for per-category accuracy, and a **benign-heavy** mix (the team picks the ratio) for time-to-report and analyst workload, closer to what a real SOC sees.

## Evaluation targets

The project brief names five metrics but no pass marks. The team proposes the targets below. They are frozen before the final test run and not changed afterwards, so results cannot be tuned to fit.

| Metric | Proposed target | Must also beat |
| --- | --- | --- |
| Triage accuracy | Recall on true threats of 0.95 or more (missing an attack is the costliest error); precision of 0.80 or more | Rules-only triage on F1 |
| Investigation completeness | 80% or more of expected IOCs and log sources found, on the overlay scenarios | Single-agent LLM with the same tools |
| Report quality | Mean rubric score of 4 out of 5 or more from at least 3 raters, with their agreement reported | Template-only reports |
| Time-to-report | Median full investigation within 60 s, and at least 10 times faster than the manual median | Manual analyst baseline |
| False action rate | Zero high-risk actions on benign alerts; 5% or less of all proposed actions outside the acceptable set | Rules-only playbook |

The report-quality rubric scores five things from 1 to 5: correctness, completeness, clarity, actionability and quality of evidence citations.

## Constraints and assumptions

**Constraints**

- 4–5 students over two semesters (3 + 12 credits).
- Free tiers only: AbuseIPDB 1,000 checks/day, VirusTotal 500 lookups/day at 4/minute, free LLM tiers with daily token caps.
- Laptops and Colab for compute; no paid cloud.
- Python, FastAPI, LangGraph, SQLite and Streamlit (React later), as decided in the architecture design.
- Actions are simulated only.

**Assumptions**

- Public datasets with a scenario overlay are close enough to real SOC data to show the approach works; the report will say where they are not.
- Alerts arrive already structured (JSON), not as free-text emails or tickets.
- One fictional organisation, one analyst role and no user login beyond a reviewer ID.
- The free LLM tiers stay available through Semester 8; if one disappears, the system falls back to another provider or a local model (NFR-REL-1).

## Traceability

Each of the seven objectives in the project brief is covered by at least one Must requirement.

| Project objective | Requirements that satisfy it |
| --- | --- |
| 1. Separate agent roles (Triage, Log-Correlation, Threat-Intel, Report) | FR-TRI-1–7, FR-COR-1–4, FR-TI-1–5, FR-REP-1–4, NFR-MAINT-2 |
| 2. Coordinator-led orchestration with tool calls and hand-offs | FR-ORC-1–3, FR-TRI-5 |
| 3. Realistic firewall, authentication and endpoint logs | FR-COR-1, DR-1–DR-3 |
| 4. IOC extraction, threat-intel enrichment and ATT&CK mapping | FR-TRI-3, FR-TI-1–5, NFR-PRIV-1 |
| 5. Structured reports with timeline, assets, severity and action | FR-REP-1–4, NFR-EXPL-1, the severity rubric |
| 6. Human approval before any simulated action | FR-HITL-1–6, FR-UI-1–3, NFR-SAFE-1–2 |
| 7. Evaluation of accuracy, investigation quality and time saved | FR-EVAL-1–4, DR-4–DR-9, NFR-REPRO-2, the evaluation targets |

The brief's methodology also asks for the alert taxonomy and severity rubric to be finalised first; that is done in the opening sections of this document.

## To be done

### Asset inventory

The severity rubric needs an inventory of the fictional organisation before it can score any alert. It must list:

- every host, with its role and tier (Low, Standard, High, Critical);
- every account, with its type (user, service, admin) and tier;
- approved scanners, admin accounts and maintenance windows, so B1 alerts can be recognised;
- which dataset entities and scenario-overlay entities each entry maps to.

Owner and deadline: to be assigned.