# Proof-of-concept alert set

The Semester 7 Triage proof of concept is trained and scored on a labelled set of 995 alerts, built by `scripts/build_poc_alerts.py` from the public datasets. This page explains how to build it, what is in it, and every labelling assumption the generator makes, so reviewers can challenge them.

It implements requirements DR-4 to DR-8 in [the requirements specification](requirements-specification.md).

## Building it

1. Download the official dataset files and place them under `data/raw/` (this folder is git-ignored):

   ```
   data/raw/unsw_nb15/*.csv          UNSW-NB15 training/testing-set CSVs (with header row)
   data/raw/cicids2017/*.csv         CICIDS2017 CSVs (MachineLearningCVE or GeneratedLabelledFlows)
   data/raw/beth/*.csv               BETH labelled_*_data.csv files
   data/raw/lanl/redteam.txt.gz      optional: LANL red-team events
   ```

2. Build and check:

   ```
   python scripts/build_poc_alerts.py
   python scripts/check_poc_alerts.py data/poc_alerts
   ```

The build is deterministic for a given seed (`--seed`, default 2026) and records the SHA-256 of every input file in `manifest.json`.

## What comes out

| File | Who reads it | Contents |
| --- | --- | --- |
| `alerts_{train,val,test}.jsonl` | The agents | One alert per line. No labels, no dataset names, no provenance. |
| `ground_truth_{train,val,test}.jsonl` | Evaluation only | The answer key per `alert_id`: category, disposition, stage, asset tier, modifiers, final severity, investigation depth, expected IOCs, expected log sources, acceptable actions, provenance. |
| `overlay.jsonl` | Audit | Every dataset value that was mapped into the fictional organisation: original IPs, hosts, users and times, and what they became. |
| `manifest.json` | Audit | Seed, input checksums, counts per split, category and disposition, and any warnings. |

## Composition (995 alerts)

| Disposition | Alerts | Where they come from |
| --- | --- | --- |
| TP | 595 | 85 per attack category C1–C7, from rows the datasets label as attacks |
| BTP | 220 | 110 B1 (authorised activity: approved scans, load tests, backups, admin maintenance, patching, helpdesk support, an announced penetration test) and 110 B2 (user error: password typos, forgotten-password lockouts, remote VPN typos, mistyped URLs) |
| FP | 180 | Deliberately loose detection rules run over rows the datasets label benign, matched to look like their TP counterparts |

Splits are roughly 60 / 20 / 20 (about 600 / 200 / 200), made separately for each (category, disposition) pair so every split has every category. The designed total is 995 (595 + 220 + 180). If a source pool runs short, the build prints a warning and the total drops.

## How leakage is prevented

- **Separate answer key.** Alerts carry no label-like field; the checker fails the build if one appears (DR-7).
- **Rules shared across dispositions.** Every detection rule produces TP alerts and BTP or FP alerts, so a rule name never gives away the answer. The checker enforces this.
- **No field gives the answer away.** Within each rule, the checker fails the build if any field is present only for TP or only for non-TP alerts.
- **Wording per split.** Each rule has ten description templates; train uses six, validation two, test two. No description or wording skeleton appears in two splits (DR-6).
- **Source groups stay in one split.** Rows from one source session (for UNSW-NB15, one attacker/victim pair within one minute; for CICIDS2017 files without IPs, a block of 20 consecutive rows) are used by only one builder, so they cannot appear in both train and test.
- **FP alerts look like TP alerts.** Each FP pool is narrowed to benign rows from the same dataset, with the same service and the same presence of a port as its TP counterpart, so which fields are filled in cannot reveal the label. The checker also fails a build if, within a rule, TP and other alerts never share a `service`, `protocol` or `source_system` value.
- **Same IP ranges for every label.** External IPs come from the IETF documentation ranges (RFC 5737) for TP, BTP and FP alike, and about a quarter of inbound TP and FP alerts come from internal hosts. No IP range correlates with the label, and an external source is a clue, not an answer: on the test build about a quarter of external-source alerts were not threats (remote-user VPN typos, the announced penetration test, the offsite backup, and FPs).
- **Real behaviour for benign activity.** Approved scans and load tests reuse real attack-behaviour rows, re-attributed to the approved scanner or test host through the overlay. The only difference from a TP scan is the context the inventory provides, which is exactly what triage must learn to check.

## Labelling assumptions

These are judgement calls. Each is applied the same way to every alert, but the team should review them.

1. **Stage from network data alone.** A flow record cannot show whether an exploit worked, so network C4 alerts are stage 1 (attempt). The exceptions are CICIDS Heartbleed, stage 2 (memory contents were returned), and Infiltration, stage 3 (the dataset labels a successful infiltration).
2. **Malware is stage 3.** BETH `evil` rows and UNSW Backdoor and Worms flows mean code is already running. Worms also set the spread modifier.
3. **Bot traffic is stage 4.** CICIDS Bot rows are command-and-control traffic from an infected host.
4. **DoS is stage 2.** The flood is happening; whether the service went down is not in the data.
5. **Modifiers.** Spread applies only from stage 2 up, to lateral-movement alerts (3–6 hosts reached) and worms. Ongoing is always false, because no dataset says whether activity continued.
6. **FP category.** An FP alert keeps the category its rule claimed (for example C1 for a port-scan rule), with disposition FP, stage 0 and severity Informational.
7. **U0 is never an answer.** U0 is something triage may output when unsure, not a ground-truth category.
8. **Acceptable actions.** Non-threats accept only `close_benign`. Threats always accept `escalate_tier2`, plus `block_ip` for an external source (or destination, for C6), credential actions for C2 and C3, and `isolate_host` from stage 3 unless the host is on the critical-asset list.
9. **Synthetic alerts.** All authentication alerts are scripted (about 24% of the set) unless a LANL red-team file is supplied, in which case 55 of the C3 alerts come from it. Both TP and BTP authentication alerts are scripted the same way, so being synthetic does not correlate with the label. The answer key marks each one `is_synthetic`.

## Known follow-ups

- **Requirements fix (done).** The requirements once listed `close_benign` as a default action for Low alerts. Low alerts are always real threats (stage 1 attempts), so the requirements now say `escalate_tier2`, or `block_ip` for a confirmed-malicious external source. The answer key never accepted `close_benign` for a threat.
- **Privacy guard in Semester 8.** The privacy guard drops reserved IP ranges before any external lookup, and the documentation ranges used here are reserved. The threat-intel replay snapshot will need to treat RFC 5737 addresses as "external for simulation" so these alerts still get a verdict.
- **Asset inventory.** `data/poc/asset_inventory.yaml` is a minimal draft (19 hosts, 13 accounts, 7 approved activities) so severity can be scored. It should grow into the full inventory listed under "To be done" in the requirements.

## Testing without the real data

`tests/fixtures/make_raw_fixture.py` writes a few thousand made-up rows in the real column formats, plus a marker file. The generator refuses to write fixture-based output to `data/poc_alerts`, and the manifest and checker both flag it. `tests/test_poc_alerts.py` builds from the fixture, runs every check, confirms the build is deterministic and tests the rubric against the five worked examples in the requirements.