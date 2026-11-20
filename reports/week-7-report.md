# Week 7 Report — System 1 Decision Model Investigation & Benchmark De-Biasing

## Objective
Investigate the root cause of the initial 100% accuracy score achieved by the System 1 baseline, identify synthetic data leakage and template memorization, and formally define modern non-autoregressive **System 1 Decision Models** (Laya, Clef, Jev) in the context of autonomous SOC alert triage.

---

## 1. Dissecting the 100% Accuracy Anomaly (Template Memorization)

A 100% accuracy score on an evaluation benchmark is a recognized indicator of data leakage or evaluation triviality. A code audit of `scripts/prepare_datasets.py` revealed the exact mechanism:

```python
# Shared Template Pool in scripts/prepare_datasets.py:
"Cobalt Strike beacon shellcode injection detected in memory of powershell.exe on {host}."
"Kerberos Pre-Authentication failure burst on domain controller {host} for account {user} from {src_ip}."
```

1. **Shared Synthetic Phrasing**:
   Although the alert corpus was partitioned into training (70%) and testing/golden benchmark (15%), **both sets sampled from the exact same parameterized sentence templates**.
2. **Feature Memorization via TF-IDF**:
   The TF-IDF vectorizer extracted unigrams and bigrams (`('cobalt', 'strike')`, `('beacon', 'shellcode')`, `('pam_unix', 'failure')`).
   The logistic regression model assigned high linear weights to these specific n-grams.
   When evaluated on test incidents, the model matched the identical token combinations. It did not perform contextual cybersecurity reasoning; it memorized template tokens.

---

## 2. Empirical Stress-Testing on Unseen Real-World Phrasing

When the TF-IDF model was evaluated on realistic alerts not present in its training templates, it failed:

```python
# Alert: "Routine Nessus vulnerability assessment scan triggered alert on port 8080"
# Expected: likely_false_positive (Authorized Administrative Scan)
# Prediction: likely_true_positive (Category: ambiguous_admin_false_positive)
# Confidence: 0.28 -> FAILED
```

Because the token `"vulnerability"` appeared in attack descriptions in the training set, the linear model misclassified an approved scan as an active intrusion with an uncalibrated confidence of **0.28**.

---

## 3. Defining the System 1 Decision Model Paradigm (Laya, Clef, Jev)

To overcome the fragility of bag-of-words classifiers without incurring the high latency and cost of autoregressive LLMs, the SOC architecture integrates the **System 1 Decision Model** paradigm:

* **Non-Autoregressive Forward Pass**: Rather than generating conversational text token-by-token (which takes seconds and risks JSON formatting errors), decision models take unstructured state (telemetry, Syslog, JSON) alongside typed schemas and resolve them in a single forward pass (**10–40 ms**).
* **Typed Decision Primitives**:
  * `choice`: Selects from a closed enumeration with calibrated probabilities.
  * `score`: Assigns an ordinal score.
  * `noul`: Outputs a mathematically calibrated boolean probability $P(\text{true})$.
* **Industry Frameworks**:
  * **Jev (TypeSafe AI)**: Commercial System 1 API for low-latency agent routing and guardrails.
  * **Laya (ConvAI Innovations)**: Open-weights model based on ModernBERT-large (~421M params, Apache 2.0) running typed decision heads via RLCD.
  * **Clef (Cloudflare)**: Edge-native decision architecture for ultra-fast classification on edge nodes.

---

## Next Increment (Week 8)
Download and integrate a small open-weights neural decision model (**<100M parameters**) from Hugging Face, implement typed decision primitives (`noul`, `choice`), and benchmark it against novel out-of-distribution security alerts.
