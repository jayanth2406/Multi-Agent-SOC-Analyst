# Semester 7 PoC Results: Triage Agent

Nov 25, 2026 · @Qwer

## Summary

On the held-out test split of 196 alerts, the hybrid Triage agent reached a threat recall of 0.91 (95% CI 0.86–0.96) and a threat precision of 0.96 (0.92–0.99). It meets the precision target and beats rules-only triage on F1, but falls short of the 0.95 recall target.

| Requirement target | Test result |
| --- | --- |
| Threat recall ≥ 0.95 | 0.91 (0.86–0.96) |
| Threat precision ≥ 0.80 | 0.96 (0.92–0.99) |
| Beat rules-only triage on F1 | Macro F1 0.91 vs 0.59 |

The 10 missed threats are all single network flows or single endpoint events that look ordinary on their own. The test split was scored once, after all choices were fixed on the validation split.

## Experimental setup

Four triage approaches were trained on the same 597 alerts, compared on 202 validation alerts, and scored once on 196 test alerts.

### Alert set

The proof-of-concept set has 995 labelled alerts built from UNSW-NB15, CICIDS2017 and BETH, plus scripted authentication activity (24% of alerts). It covers all 9 ground-truth categories (C1–C7, B1, B2).

| Split | Alerts | TP | BTP | FP |
| --- | --- | --- | --- | --- |
| Train | 597 | 357 | 132 | 108 |
| Validation | 202 | 121 | 44 | 37 |
| Test | 196 | 117 | 44 | 35 |
| Total | 995 | 595 | 220 | 180 |

Leakage checks passed before any training. No description, wording template or source session appears in more than one split. No alert field reveals its label, and every detection rule produces both threats and non-threats.

### Approaches compared

| Approach | How it decides |
| --- | --- |
| Rules | Rule → category; approved activity → B1; single-user login errors → B2; everything else treated as a threat |
| Structured | Gradient-boosting model on alert fields and asset-inventory context, including command-line tokens |
| TF-IDF | Logistic regression on the alert description text only |
| Hybrid (the agent) | Rules for approved activity and user errors; the structured model for the rest, dismissing an alert only when it is confident |

### Choices fixed on validation

The hybrid's dismiss cutoff (0.50) was the lowest that kept validation threat recall at 0.95. Each approach's confidence threshold for forcing a full investigation was the lowest that routed at most 2% of must-be-full alerts light; for the hybrid this was 0.99. Nothing was changed after the test split was scored.

Severity is computed the same way for every approach: a provisional attack stage per category, combined with the asset tier using the severity rubric.

## Results on the test split

The hybrid and structured approaches tie on every disposition metric and are far ahead of rules and TF-IDF. The hybrid is the agent because the rules make its benign decisions explainable.

| Metric (test, n = 196) | Rules | Structured | TF-IDF | Hybrid |
| --- | --- | --- | --- | --- |
| Threat recall | 1.00 (1.00–1.00) | 0.91 (0.86–0.96) | 0.73 (0.64–0.80) | **0.91 (0.86–0.96)** |
| Threat precision | 0.74 (0.67–0.81) | 0.96 (0.92–0.99) | 0.79 (0.72–0.87) | **0.96 (0.92–0.99)** |
| Disposition macro F1 | 0.59 (0.56–0.62) | 0.91 (0.87–0.95) | 0.64 (0.58–0.71) | **0.91 (0.87–0.95)** |
| Category accuracy | 0.97 (0.94–0.99) | 1.00 (1.00–1.00) | 0.73 (0.67–0.79) | **1.00 (1.00–1.00)** |
| Severity exact match | 0.79 | 0.92 | 0.69 | **0.92** |
| Severity underestimated | 0.01 | 0.06 | 0.20 | **0.06** |
| Must-be-full alerts routed light | 0.00 | 0.00 | 0.00 | **0.00** |
| Share routed to full investigation | 0.85 | 0.82 | 0.96 | **0.83** |

Brackets are 95% bootstrap intervals (1,000 resamples).

### Recall per disposition

| Approach | TP (n = 117) | BTP (n = 44) | FP (n = 35) |
| --- | --- | --- | --- |
| Rules | 1.00 | 0.86 | 0.00 |
| Structured | 0.91 | 1.00 | 0.86 |
| TF-IDF | 0.73 | 0.91 | 0.34 |
| Hybrid | 0.91 | 1.00 | 0.86 |

Three findings follow:

- **Rules cannot see false positives.** They catch every threat but flag all 35 false positives as threats, so analysts would chase every false alarm.
- **The wording carries little signal.** TF-IDF on the description is the weakest approach on threat recall (0.73) and underestimates severity for 20% of alerts. The useful information is in the alert's fields and the asset-inventory context.
- **The hybrid recognises benign activity perfectly** (BTP recall 1.00). Because the benign alerts were built from the asset inventory's approved activity, an inventory lookup is expected to do well here; it is the check a triage analyst should make.

## Validation vs test

Threat recall fell from 0.95 on validation to 0.91 on test, about 4 alerts; precision and the benign results held steady.

| Hybrid agent | Validation (n = 202) | Test (n = 196) |
| --- | --- | --- |
| Threat recall | 0.95 (0.91–0.98) | 0.91 (0.86–0.96) |
| Threat precision | 0.95 (0.91–0.98) | 0.96 (0.92–0.99) |
| Disposition macro F1 | 0.93 (0.89–0.96) | 0.91 (0.87–0.95) |
| FP recall | 0.84 | 0.86 |
| BTP recall | 1.00 | 1.00 |
| Severity exact match | 0.93 | 0.92 |
| Severity underestimated | 0.03 | 0.06 |
| Must-be-full alerts routed light | 0.01 | 0.00 |
| Missed threats | 6 of 121 | 10 of 117 |

The drop is the expected cost of choosing the dismiss cutoff on validation. The cutoff was set to the lowest value that just reached 0.95 recall there, so on unseen alerts recall was likely to land slightly lower. The two intervals overlap, and with about 120 threats per split each missed threat moves recall by almost one point.

## Error analysis

All 10 missed threats on test are single network flows or single endpoint events that resemble normal activity when seen alone.

| Source of the missed alert | Dataset label | Missed (test) | Missed (validation) |
| --- | --- | --- | --- |
| Network brute force | CICIDS2017 SSH-Patator | 3 | 0 |
| Network brute force | CICIDS2017 FTP-Patator | 0 | 1 |
| Endpoint process event | BETH evil | 3 | 3 |
| Denial of service | CICIDS2017 DoS Hulk | 2 | 1 |
| Denial of service | CICIDS2017 DoS GoldenEye | 1 | 0 |
| Exploit | UNSW-NB15 Exploits | 1 | 0 |
| Malware traffic | UNSW-NB15 Worms | 0 | 1 |
| **Total** |  | **10** | **6** |

**Endpoint events.** The likely cause is that BETH marks routine events of a malicious process (such as opening or closing a file) as evil, and those look the same as events from normal processes. Adding command-line tokens to the model improved false-positive detection on validation (FP recall 0.81 to 0.84) but did not recover these three, which is consistent with that explanation. It still needs confirming by checking the event types in the error file.

**Network flows.** The false-positive alerts were deliberately drawn from benign flows with the same dataset, service and port shape as the attack flows, so that no field would give away the label. One flow of a brute force or a flood can therefore look like an ordinary session.

**Severity.** Each missed threat is scored as a non-threat, so its severity drops to Informational. That accounts for most of the 6% of alerts whose severity was underestimated; the rest are worm alerts, where triage cannot see that the worm has spread.

### Routing caveat

"Must-be-full alerts routed light" was 0.00 on test, but that does not mean every missed threat received a full investigation. The metric counts only alerts whose correct depth is full. A missed brute force against an ordinary workstation is correctly Low severity, so its correct depth was light anyway. How many of the 10 were still sent to full investigation by the asset-tier or confidence safeguards is recorded per alert in `results/triage_poc_test_errors.jsonl`. Every alert, missed or not, still reaches the analyst queue.

## Limitations

These results come from one fixed split of a partly synthetic alert set, so they show the approach works rather than how it would perform in a real SOC.

- **Small test split.** 196 alerts, 117 of them threats. Each missed threat moves recall by almost one point, and the recall interval spans 0.86 to 0.96.
- **One split, one seed.** All results come from a single train/validation/test split with seed 2026; no repeated splits or cross-validation.
- **Partly synthetic data.** All authentication alerts (24% of the set) are scripted, because the LANL red-team file was not available. Network and endpoint alerts come from real dataset rows, mapped into one fictional organisation.
- **Community copies of the datasets.** UNSW-NB15 and BETH were taken from Hugging Face re-uploads. The UNSW-NB15 copy has 2,280,090 rows, fewer than the official release, and is probably deduplicated or partial. Input checksums are recorded in the alert set's manifest.
- **Benign activity follows the inventory.** Approved-activity alerts were generated from the same asset inventory the agent consults, so BTP recall of 1.00 measures whether the inventory check works, not how well it would handle undocumented admin activity.
- **Thresholds chosen on validation.** The dismiss cutoff and confidence threshold were picked on validation without a safety margin, which is the main reason recall fell on test.
- **No threat intelligence or log correlation.** Triage was scored alone. The malicious-IOC safeguard was not active, and nothing outside the alert itself was used to confirm or dismiss it.
