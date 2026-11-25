"""Compare three triage approaches on the PoC alert set.

    python scripts/triage_experiment.py                 # train on train, score on val
    python scripts/triage_experiment.py --split test    # the one-time final score

A. rules      rule -> category, approved activity -> B1, user-error heuristic -> B2, else TP
B. structured gradient boosting on alert fields plus asset-inventory context
C. tfidf      logistic regression on the alert description text only

Each approach predicts a category and a disposition (TP / BTP / FP). Severity and
light/full routing are then computed the same way for all three, from the
severity rubric and the asset inventory.

Model choice and the confidence threshold are made on val. Score on test once,
at the end, and report that number: re-running on test after changes turns it
into a second validation set.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.triage.features import Context, route_one, rules_predict  # noqa: E402
from backend.triage.inventory import Inventory  # noqa: E402
from backend.triage.model import THREAT_SIDE, TriageModel  # noqa: E402
from backend.triage.rubric import LEVELS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SEED = 2026
DISPOSITIONS = ["TP", "BTP", "FP"]
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
MAX_UNDER_INVESTIGATED = 0.02
TARGET_THREAT_RECALL = 0.95  # from the requirements' evaluation targets
DISMISS_CUTOFFS = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.97, 0.99]  # share of must-be-full alerts we accept routing light, when choosing the threshold


def load(folder: Path, split: str):
    alerts = [json.loads(x) for x in (folder / f"alerts_{split}.jsonl").read_text().splitlines() if x.strip()]
    truth = {g["alert_id"]: g for g in
             (json.loads(x) for x in (folder / f"ground_truth_{split}.jsonl").read_text().splitlines() if x.strip())}
    return alerts, [truth[a["alert_id"]] for a in alerts]


# ----------------------------------------------------------------------------- models

class StructuredModel:
    """B. The trained model on its own: most likely class, no rules, no cutoff."""
    name = "structured"

    def __init__(self, ctx):
        self.model = TriageModel(ctx, seed=SEED)

    def fit(self, alerts, truth):
        self.model.fit(alerts, truth)
        return self

    def predict(self, alerts):
        return self.model.argmax_all(alerts)


class TextModel:
    name = "tfidf"

    def __init__(self, ctx):
        def pipe():
            return make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True),
                                 LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0))
        self.cat, self.disp = pipe(), pipe()

    def fit(self, alerts, truth):
        texts = [a["description"] for a in alerts]
        self.cat.fit(texts, [g["category"] for g in truth])
        self.disp.fit(texts, [g["disposition"] for g in truth])
        return self

    def predict(self, alerts):
        texts = [a["description"] for a in alerts]
        proba = self.disp.predict_proba(texts)
        return list(self.cat.predict(texts)), list(self.disp.classes_[proba.argmax(1)]), list(proba.max(1))


class RulesModel:
    name = "rules"

    def __init__(self, ctx):
        self.ctx = ctx

    def fit(self, alerts, truth):
        return self

    def predict(self, alerts):
        out = [rules_predict(a, self.ctx) for a in alerts]
        return [o[0] for o in out], [o[1] for o in out], [o[2] for o in out]


class HybridModel:
    """D. What the Triage agent runs: backend.triage.model.TriageModel (see its docstring)."""
    name = "hybrid"

    def __init__(self, ctx):
        self.model = TriageModel(ctx, seed=SEED)

    def fit(self, alerts, truth):
        self.model.fit(alerts, truth)
        return self

    def calibrate(self, alerts, truth):
        self.model.calibrate(alerts, truth, TARGET_THREAT_RECALL, DISMISS_CUTOFFS)
        return self

    @property
    def cutoff(self):
        return self.model.dismiss_cutoff

    @property
    def cutoff_met(self):
        return self.model.dismiss_cutoff_met

    def predict(self, alerts):
        out = self.model.decide_all(alerts)
        return [o[0] for o in out], [o[1] for o in out], [o[2] for o in out]


# ----------------------------------------------------------------------------- scoring

def route(alerts, cats, disps, confs, ctx, threshold):
    """Light or full for each alert, using the same routing as the Triage agent (stateless safeguards)."""
    levels, depths = [], []
    for a, c, d, conf in zip(alerts, cats, disps, confs):
        _, _, level, depth, _ = route_one(a, c, d, conf, ctx, threshold)
        levels.append(level)
        depths.append(depth)
    return levels, depths


def metrics(truth, cats, disps, levels, depths):
    y_threat = np.array([g["disposition"] == "TP" for g in truth])
    p_threat = np.array([d in THREAT_SIDE for d in disps])  # needs_investigation is not a dismissal
    tp = int((y_threat & p_threat).sum())
    gt_full = np.array([g["investigation_depth"] == "full" for g in truth])
    routed_light = np.array([d == "light" for d in depths])
    gt_level = np.array([LEVELS.index(g["final_severity"]) for g in truth])
    p_level = np.array([LEVELS.index(lv) for lv in levels])
    return {
        "threat_recall": tp / max(int(y_threat.sum()), 1),
        "threat_precision": tp / max(int(p_threat.sum()), 1),
        "disposition_macro_f1": f1_score([g["disposition"] for g in truth], disps, labels=DISPOSITIONS,
                                         average="macro", zero_division=0),
        "category_accuracy": float(np.mean([g["category"] == c for g, c in zip(truth, cats)])),
        "severity_exact": float(np.mean(gt_level == p_level)),
        "severity_under": float(np.mean(p_level < gt_level)),
        "under_investigated": float((gt_full & routed_light).sum() / max(int(gt_full.sum()), 1)),
        "share_routed_full": float(np.mean(~routed_light)),
    }


def per_class(truth, disps):
    out = {}
    for d in DISPOSITIONS:
        y = np.array([g["disposition"] == d for g in truth])
        p = np.array([x == d for x in disps])
        out[d] = {"n": int(y.sum()), "recall": float((y & p).sum() / max(int(y.sum()), 1)),
                  "precision": float((y & p).sum() / max(int(p.sum()), 1))}
    return out


def bootstrap(truth, cats, disps, levels, depths, n=1000):
    rng = np.random.RandomState(SEED)
    idx = np.arange(len(truth))
    keys = ("threat_recall", "threat_precision", "disposition_macro_f1", "category_accuracy")
    samples = {k: [] for k in keys}
    for _ in range(n):
        s = rng.choice(idx, len(idx), replace=True)
        m = metrics([truth[i] for i in s], [cats[i] for i in s], [disps[i] for i in s],
                    [levels[i] for i in s], [depths[i] for i in s])
        for k in keys:
            samples[k].append(m[k])
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in samples.items()}


def pick_threshold(alerts, truth, cats, disps, confs, ctx):
    """Lowest confidence threshold that keeps under-investigation at or below the target.

    Returns (threshold, target_met). If no threshold meets the target, the highest is used.
    """
    for t in THRESHOLDS:
        levels, depths = route(alerts, cats, disps, confs, ctx, t)
        if metrics(truth, cats, disps, levels, depths)["under_investigated"] <= MAX_UNDER_INVESTIGATED:
            return t, True
    return THRESHOLDS[-1], False


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=ROOT / "data" / "poc_alerts")
    ap.add_argument("--inventory", type=Path, default=ROOT / "data" / "poc" / "asset_inventory.yaml")
    ap.add_argument("--split", choices=["val", "test"], default="val")
    ap.add_argument("--out", type=Path, default=ROOT / "results")
    ap.add_argument("--model-out", type=Path, default=ROOT / "models" / "triage_poc.joblib",
                    help="where to save the hybrid model the Triage agent loads")
    ap.add_argument("--bootstrap", type=int, default=1000, help="resamples for the 95%% intervals")
    args = ap.parse_args(argv)

    manifest = json.loads((args.data / "manifest.json").read_text())
    ctx = Context(Inventory(args.inventory))
    train_a, train_t = load(args.data, "train")
    val_a, val_t = load(args.data, "val")
    eval_a, eval_t = (val_a, val_t) if args.split == "val" else load(args.data, "test")

    results = {"split": args.split, "n_train": len(train_a), "n_eval": len(eval_a),
               "alert_set_fixture": manifest.get("fixture", False),
               "generator_version": manifest.get("generator_version"), "approaches": {}}
    fitted = {}
    errors = []
    for cls in (RulesModel, StructuredModel, TextModel, HybridModel):
        model = cls(ctx).fit(train_a, train_t)
        if hasattr(model, "calibrate"):
            model.calibrate(val_a, val_t)  # always on val
        fitted[model.name] = model
        threshold, target_met = pick_threshold(val_a, val_t, *model.predict(val_a), ctx)  # always chosen on val
        cats, disps, confs = model.predict(eval_a)
        levels, depths = route(eval_a, cats, disps, confs, ctx, threshold)
        errors += list_errors(model.name, eval_a, eval_t, cats, disps, confs, levels, depths)
        results["approaches"][model.name] = {
            "confidence_threshold": threshold, "routing_target_met_on_val": target_met,
            "metrics": metrics(eval_t, cats, disps, levels, depths),
            "ci95": bootstrap(eval_t, cats, disps, levels, depths, n=args.bootstrap),
            "per_disposition": per_class(eval_t, disps),
        }

    args.out.mkdir(parents=True, exist_ok=True)
    out_file = args.out / f"triage_poc_{args.split}.json"
    out_file.write_text(json.dumps(results, indent=2) + "\n")
    hybrid = fitted["hybrid"].model
    hybrid.confidence_threshold = results["approaches"]["hybrid"]["confidence_threshold"]
    hybrid.save(args.model_out, trained_on=str(args.data), generator_version=manifest.get("generator_version"),
                n_train=len(train_a), val_metrics=results["approaches"]["hybrid"]["metrics"]
                if args.split == "val" else None)

    results["approaches"]["hybrid"]["dismiss_cutoff"] = fitted["hybrid"].cutoff
    results["approaches"]["hybrid"]["dismiss_cutoff_met_on_val"] = fitted["hybrid"].cutoff_met
    err_file = args.out / f"triage_poc_{args.split}_errors.jsonl"
    err_file.write_text("".join(json.dumps(e) + "\n" for e in errors))
    out_file.write_text(json.dumps(results, indent=2) + "\n")

    report(results)
    summarise_errors(errors, ("structured", "hybrid"))
    print(f"every error, per approach: {err_file}")
    print(f"\nsaved {out_file.relative_to(ROOT) if out_file.is_relative_to(ROOT) else out_file}")
    if args.split == "test":
        print("This is the one-time test score. Don't tune anything further against it.")


def list_errors(name, alerts, truth, cats, disps, confs, levels, depths):
    """One record per alert an approach got wrong in a way that matters."""
    out = []
    for a, g, c, d, conf, lv, dp in zip(alerts, truth, cats, disps, confs, levels, depths):
        kinds = []
        if g["disposition"] == "TP" and d not in THREAT_SIDE:
            kinds.append("missed_threat")
        if g["disposition"] != "TP" and d in THREAT_SIDE:
            kinds.append("false_alarm")
        if g["disposition"] != "TP" and d not in THREAT_SIDE and g["disposition"] != d:
            kinds.append("wrong_benign_label")
        if g["investigation_depth"] == "full" and dp == "light":
            kinds.append("under_investigated")
        if LEVELS.index(lv) < LEVELS.index(g["final_severity"]):
            kinds.append("severity_too_low")
        if kinds:
            pv = g["provenance"]
            out.append({"approach": name, "alert_id": a["alert_id"], "errors": kinds, "rule": a["rule_id"],
                        "truth": {"category": g["category"], "disposition": g["disposition"], "stage": g["stage"],
                                  "tier": g["asset_tier"], "severity": g["final_severity"],
                                  "depth": g["investigation_depth"]},
                        "predicted": {"category": c, "disposition": d, "confidence": round(float(conf), 3),
                                      "severity": lv, "depth": dp},
                        "source": {"builder": pv["builder"], "dataset": pv["dataset"], "raw_label": pv["raw_label"]},
                        "description": a["description"]})
    return out


def summarise_errors(errors, names):
    from collections import Counter
    for n in names:
        mine = [e for e in errors if e["approach"] == n]
        for kind in ("missed_threat", "under_investigated", "severity_too_low"):
            c = Counter(f"{e['source']['builder']} ({e['source']['raw_label']})" for e in mine if kind in e["errors"])
            if c:
                print(f"\n{n}: {kind.replace('_', ' ')} x{sum(c.values())}: "
                      + ", ".join(f"{k} x{v}" for k, v in c.most_common()))


def report(r):
    print(f"\nTriage PoC on {r['split']} ({r['n_eval']} alerts, trained on {r['n_train']})")
    if r["alert_set_fixture"]:
        print("NOTE: built from made-up fixture rows. These numbers mean nothing.")
    rows = [("Threat recall", "threat_recall"), ("Threat precision", "threat_precision"),
            ("Disposition macro F1", "disposition_macro_f1"), ("Category accuracy", "category_accuracy"),
            ("Severity exact match", "severity_exact"), ("Severity underestimated", "severity_under"),
            ("Under-investigated (should be full, routed light)", "under_investigated"),
            ("Share routed to full investigation", "share_routed_full")]
    names = list(r["approaches"])
    print(f"\n| Metric | {' | '.join(names)} |")
    print("|---|" + "---|" * len(names))
    for label, key in rows:
        cells = []
        for n in names:
            v = r["approaches"][n]["metrics"][key]
            ci = r["approaches"][n]["ci95"].get(key)
            cells.append(f"{v:.2f}" + (f" ({ci[0]:.2f}-{ci[1]:.2f})" if ci else ""))
        print(f"| {label} | {' | '.join(cells)} |")
    print("| Confidence threshold (chosen on val) | "
          + " | ".join(f"{r['approaches'][n]['confidence_threshold']:.2f}"
                       + ("" if r["approaches"][n]["routing_target_met_on_val"] else " (target missed)")
                       for n in names) + " |")
    h = r["approaches"].get("hybrid")
    if h:
        print(f"| Hybrid dismiss cutoff (chosen on val) | | | | {h['dismiss_cutoff']:.2f}"
              + ("" if h["dismiss_cutoff_met_on_val"] else " (recall target missed: never dismisses)") + " |")
    print(f"\nRouting target: at most {MAX_UNDER_INVESTIGATED:.0%} of alerts that need a full investigation "
          "routed light, on val.")
    print("\nRecall per disposition:")
    for n in names:
        pc = r["approaches"][n]["per_disposition"]
        print(f"  {n:<11}" + "  ".join(f"{d} {pc[d]['recall']:.2f} (n={pc[d]['n']})" for d in DISPOSITIONS))


if __name__ == "__main__":
    main()
