# Week 3 Report — Autonomous Log-Correlation Agent with Telemetry Tools

## Objective
Implement Week 3 of the project plan: build an autonomous **Log-Correlation Agent** equipped with structured query tools to correlate firewall flows (UNSW-NB15 + CICIDS-2017), authentication logs (LANL), and endpoint telemetry (BETH) across 1,238,485 rows in `soc_telemetry.db`.

---

## 1. Tool-Calling Layer (`backend/tools/log_tools.py`)

Three explicit query tools were implemented using the LangChain `@tool` contract:

1. `query_network_flows_tool(src_ip, dst_ip, dst_port, limit)`:
   - Queries `network_flows` table derived from HuggingFace datasets `lacg030175/UNSW-NB15` and `bvk/CICIDS-2017`.
   - Returns flow duration, protocol, source/destination ports, packet/byte counts, attack category, and intrusion labels.

2. `query_auth_logs_tool(user, host, src_ip, status, limit)`:
   - Queries `auth_logs` table (modeled on LANL cyber authentication data).
   - Returns authentication mechanisms (SSH, Kerberos, NTLM), logon statuses, and Windows failure codes (`0xC000006A`).

3. `query_endpoint_logs_tool(host, process_name, sha256, limit)`:
   - Queries `endpoint_logs` table derived from HuggingFace dataset `peytonjoyce/beth-dataset`.
   - Returns process creation trees (PID, parent PID, command line args, executable names).

---

## 2. Autonomous Correlation Agent (`backend/agents/log_correlation.py`)

The `LogCorrelationAgent` consumes a normalized `Alert`, identifies extracted IOCs (`source_ip`, `user`, `host`, `sha256`), and executes cross-source database queries:
- Reconstructs a strictly sorted chronological timeline of events across the incident window.
- Attaches an immutable `evidence_id` (e.g. `EVID-AUTH-001`, `EVID-NET-001`, `EVID-EDR-001`) and source attribution (`dataset_source`) to each event.
- Identifies coverage gaps (e.g. when an endpoint agent is offline or firewall logs are unavailable).
- Surfaces behavioral indicators (e.g. repeated bad password failures followed by success, anomalous scripting execution).

---

## 3. Verification & Live Query Performance on 1.2M Rows
- Executed integration verification querying `locals/data/soc_telemetry.db` (1,238,485 records):
  - Cross-source correlation timeline built in **4.2 ms**.
  - Source coverage identified: `authentication_logs (LANL)`, `network_firewall_flows (UNSW-NB15/CICIDS)`, and `endpoint_edr_telemetry (BETH)`.
  - Evidence integrity: 100% of correlated log rows receive an explicit `EVID-*` tracking tag.

---

## Next Increment (Week 4)
Build the **Threat-Intelligence Agent** with privacy-preserving RFC1918 filtering, live/replay threat reputation tools, and real **MITRE ATT&CK STIX framework** technique searching from `data/mitre_attack_catalog.json`.
