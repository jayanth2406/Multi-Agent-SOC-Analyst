# Triage agent (v1)

The Semester 7 proof of concept: one agent that triages each alert using the taxonomy, the severity rubric and the light/full routing in the [requirements specification](requirements-specification.md) (FR-TRI-1 to FR-TRI-7).

## Run it

1. Build the alert set (see [poc-alert-set.md](poc-alert-set.md)).
2. Train and compare, which also saves the model the agent loads:

   ```
   python scripts/triage_experiment.py
   ```

   This writes `models/triage_poc.joblib`, `results/triage_poc_val.json` and the per-alert error list.

3. Start the API and send an alert:

   ```
   uvicorn backend.main:app --reload
   ```

   `POST /api/v1/triage` takes one alert, and `POST /api/v1/triage/batch` takes a list. Alerts use the format of `data/poc_alerts/alerts_*.jsonl`. The older field names `source_ip` and `destination_ip` are also accepted.

## How it decides

1. **Rules first.** An alert that fits an approved activity in the asset inventory (actor, target and time window) is B1. One account with a few failed logins from its own machine or the VPN is B2. Both are BTP.
2. **Then the model.** A gradient-boosting model on the alert's fields and inventory context, including command-line tokens for EDR alerts, gives the probability that the alert is a real threat. It dismisses an alert (BTP or FP) only when the probability that it is not a threat reaches the **dismiss cutoff**, chosen on validation to keep threat recall at 0.95 or more.
3. **Unclear category.** A threat whose category the model is less than 50% sure of becomes U0 with disposition `needs_investigation`.
4. **Severity.** Each category has a cautious provisional stage, for example C4 = attempt, because triage can't see whether an exploit worked. The stage and the asset tier then give the severity from the rubric.
5. **Routing.** Informational and Low alerts get a light investigation, and everything else a full one. A safeguard upgrades light to full when:
   - the asset is High or Critical tier;
   - the category is U0;
   - the confidence is below a threshold chosen on validation; or
   - the same source IP or account has appeared in 5 or more alerts in 24 hours.

   The malicious-IOC safeguard needs threat intelligence and arrives in Semester 8. Each decision lists it under `safeguards_not_checked`.

Every decision includes typed IOCs (internal IPs kept apart from external ones), the log sources a full investigation should query, and a reasoning summary in plain English.

With no model file, the agent falls back to the rules alone. Anything the rules can't clear is treated as a threat and sent to full investigation.

## Where the code is

| Path | What it holds |
| --- | --- |
| `backend/agents/triage_agent.py` | The agent: decision, routing, IOCs, reasoning |
| `backend/triage/model.py` | The trained model and its decision rule |
| `backend/triage/features.py` | Inventory lookups, rules, features, provisional severity, routing |
| `backend/triage/rubric.py`, `inventory.py` | Taxonomy, severity table, the asset inventory |
| `scripts/triage_experiment.py` | Trains and compares the approaches; uses the same code as the agent |

Because the agent and the experiment share one code path, the experiment's "hybrid" numbers describe the agent. `tests/test_triage_agent.py` checks that they agree alert by alert.

## Known limits

- **Single-event and single-flow alerts.** Some attacks look ordinary as one event or one flow: a `close` event from a malicious process, or one flow of a DoS. Triage alone can't catch these; finding the rest of the attack is the log-correlation agent's job.
- **Approved activity on important servers still gets a full investigation.** The asset-tier safeguard applies to every alert, so an approved backup from a High-tier server is routed full. That follows the requirements as written; the team may want to exempt matched approved activity.
- **Thresholds are not final.** The dismiss cutoff and the confidence threshold are both chosen on validation, which flatters the validation scores. The test split is scored once, at the end.
- **Not yet in the full pipeline.** The LangGraph pipeline (`/alerts/investigate`) still uses the older keyword agent in `backend/agents/triage.py`. Moving it onto this agent is Semester 8 orchestration work.
