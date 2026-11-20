# Week 4 Report — Threat-Intelligence Agent & MITRE ATT&CK STIX Integration

## Objective
Implement Week 4 of the semester-long plan: build an autonomous **Threat-Intelligence Agent** equipped with privacy-preserving indicator enrichment tools and direct integration with the **MITRE ATT&CK Enterprise Matrix**.

---

## 1. Tool-Calling Layer (`backend/tools/threat_intel_tools.py`)

Three threat intelligence tools were implemented using the LangChain `@tool` contract:

1. `lookup_ip_reputation_tool(ip: str)`:
   - **RFC1918 Privacy Guard**: Evaluates incoming IPs with `ipaddress.ip_address()`. Internal addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback) are flagged as `internal_asset` and blocked from external querying.
   - For public routable addresses, queries AbuseIPDB community reputation endpoints / replay cache, returning confidence scores and historical reporting volume.

2. `lookup_file_hash_tool(sha256: str)`:
   - Queries VirusTotal community threat database / replay cache for binary hashes (`sha256`, `md5`).
   - Returns detection ratios (e.g. 58/72 AV scanners) and malware family signatures (e.g. Cobalt Strike, Generic Trojan).

3. `search_mitre_attack_tool(keyword: str, tactic: str | None)`:
   - Queries the local STIX-derived MITRE ATT&CK Enterprise Catalog (`data/mitre_attack_catalog.json`).
   - Retrieves matching technique IDs (`T1110`, `T1046`, `T1059`, `T1071`, `T1078`), tactics (Credential Access, Discovery, Execution, C2), subtechniques, and detection guidance.

---

## 2. Threat-Intelligence Agent (`backend/agents/threat_intel.py`)

The `ThreatIntelligenceAgent` consumes an `Alert` along with extracted IOCs and autonomously invokes threat intelligence tools:
- Separates external hostile infrastructure from internal assets without data leakage.
- Correlates observed behavior with official MITRE ATT&CK techniques.
- Computes `highest_threat_score` to guide the coordinator and downstream reporting.

---

## 3. Verification & Live Execution
- Verified IP privacy isolation: `10.0.0.1` was identified as `internal_asset` with external lookups blocked.
- Hostile IP detection: `185.220.101.5` was classified as `malicious` (Abuse confidence score: 0.94).
- MITRE STIX correlation: Successfully retrieved Technique `T1110` (Brute Force) under `Credential Access` tactic.

---

## Next Increment (Week 5)
Implement the **Human-in-the-Loop Analyst Dashboard** in Streamlit (`ui/app.py`), enabling an analyst to view queued alerts, inspect correlated multi-agent timelines, and click **Approve / Edit / Reject** on proposed response actions.
