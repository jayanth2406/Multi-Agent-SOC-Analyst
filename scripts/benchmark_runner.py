"""Stress-testing and benchmarking runner for Multi-Agent SOC Analyst.

Evaluates:
  1. Rules Baseline (Deterministic)
  2. System 1 Fast Decision Model (<500MB local statistical classifier)
  3. Full LangGraph Multi-Agent Collaborative Pipeline
against the Golden Benchmark dataset (locals/benchmarks/golden_soc_benchmark.json).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agents.system1_decision import system1_model
from backend.agents.triage import DeterministicTriageAgent
from backend.models.schemas import Alert
from backend.orchestration.graph import soc_orchestrator

BENCHMARK_FILE = Path("locals/benchmarks/golden_soc_benchmark.json")
OUTPUT_FILE = Path("locals/benchmarks/benchmark_results.json")


def run_benchmark():
    if not BENCHMARK_FILE.exists():
        print(f"Error: Benchmark file {BENCHMARK_FILE} not found. Run scripts/prepare_datasets.py first.")
        return

    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        bench_data = json.load(f)

    alerts = [Alert(**item) for item in bench_data]
    total = len(alerts)
    print(f"\n=======================================================")
    print(f"  Multi-Agent SOC Analyst — Golden Benchmark Suite")
    print(f"  Evaluating {total} Golden Benchmark Incidents")
    print(f"=======================================================\n")

    rules_agent = DeterministicTriageAgent()

    # --- Mode 1: Rules Baseline ---
    t0 = time.perf_counter()
    rules_correct_class = 0
    rules_correct_cat = 0
    for a in alerts:
        res = rules_agent.triage(a)
        gt_class = a.metadata.get("ground_truth_classification")
        gt_cat = a.metadata.get("ground_truth_category")
        if res.classification == gt_class:
            rules_correct_class += 1
        if res.category == gt_cat:
            rules_correct_cat += 1
    t_rules = (time.perf_counter() - t0) * 1000 / total

    # --- Mode 2: System 1 Fast Decision Model ---
    t0 = time.perf_counter()
    s1_correct_class = 0
    s1_correct_cat = 0
    for a in alerts:
        res = system1_model.predict(a)
        gt_class = a.metadata.get("ground_truth_classification")
        gt_cat = a.metadata.get("ground_truth_category")
        if res.classification == gt_class:
            s1_correct_class += 1
        if res.category == gt_cat:
            s1_correct_cat += 1
    t_s1 = (time.perf_counter() - t0) * 1000 / total

    # --- Mode 3: LangGraph Multi-Agent Pipeline ---
    t0 = time.perf_counter()
    ma_correct_disposition = 0
    total_evidence_collected = 0
    total_actions_proposed = 0
    for a in alerts:
        state = {
            "alert": a,
            "triage_finding": None,
            "correlation_finding": None,
            "threat_intel_finding": None,
            "incident_report": None,
            "system1_used": False,
            "status": "started",
            "errors": [],
        }
        res = soc_orchestrator.invoke(state)
        report = res.get("incident_report")
        if report:
            total_evidence_collected += len(report.evidence_citations)
            total_actions_proposed += len(report.proposed_actions)
            gt_class = a.metadata.get("ground_truth_classification")
            if (gt_class == "likely_true_positive" and report.disposition == "confirmed_incident") or \
               (gt_class == "likely_false_positive" and report.disposition == "false_positive"):
                ma_correct_disposition += 1
    t_ma = (time.perf_counter() - t0) * 1000 / total

    # Summary Results
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_evaluated": total,
        "metrics": {
            "rules_baseline": {
                "classification_accuracy": round(rules_correct_class / total * 100, 2),
                "category_accuracy": round(rules_correct_cat / total * 100, 2),
                "avg_latency_ms": round(t_rules, 3),
            },
            "system1_decision_model": {
                "classification_accuracy": round(s1_correct_class / total * 100, 2),
                "category_accuracy": round(s1_correct_cat / total * 100, 2),
                "avg_latency_ms": round(t_s1, 3),
            },
            "multi_agent_pipeline": {
                "disposition_accuracy": round(ma_correct_disposition / total * 100, 2),
                "avg_latency_ms": round(t_ma, 3),
                "total_evidence_citations": total_evidence_collected,
                "avg_evidence_per_incident": round(total_evidence_collected / total, 1),
                "total_remediation_actions": total_actions_proposed,
            },
        },
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Print Table
    print(f"| Model / Architecture | Accuracy | Latency (per alert) | Depth & Capabilities |")
    print(f"|---|---|---|---|")
    print(f"| **Rules Baseline** | {results['metrics']['rules_baseline']['classification_accuracy']}% | {results['metrics']['rules_baseline']['avg_latency_ms']} ms | Deterministic rule matching |")
    print(f"| **System 1 Fast Model (<500MB)** | {results['metrics']['system1_decision_model']['classification_accuracy']}% | {results['metrics']['system1_decision_model']['avg_latency_ms']} ms | Statistical inference (92KB model) |")
    print(f"| **Multi-Agent Collaborative Pipeline** | {results['metrics']['multi_agent_pipeline']['disposition_accuracy']}% | {results['metrics']['multi_agent_pipeline']['avg_latency_ms']} ms | Cross-source correlation, TI, MITRE, Evidence citations |")
    print(f"\nFull benchmark report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_benchmark()
