"""The triage model: rules for benign activity, a gradient-boosting model for the rest.

This is the "hybrid" approach measured by scripts/triage_experiment.py. The
Triage agent loads the saved file and calls the same `decide`, so the
experiment's numbers describe the agent's behaviour.

Decision for one alert:
  1. Rules first: approved activity -> B1/BTP, single-user error -> B2/BTP.
  2. Otherwise the model gives P(TP). The alert is dismissed (BTP or FP) only if
     1 - P(TP) reaches the dismiss cutoff, chosen on validation data to keep
     threat recall at or above the target.
  3. A threat whose category the model is unsure of (top probability below
     U0_BELOW) becomes U0 / needs_investigation.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction import DictVectorizer

from backend.triage.features import RULE_CATEGORY, Context, features, rules_predict

ATTACK_CATEGORIES = sorted(set(RULE_CATEGORY.values()))
THREAT_SIDE = ("TP", "needs_investigation")  # dispositions that are not dismissals
FORMAT_VERSION = 1


class TriageModel:
    MIN_TOKEN_COUNT = 3  # command-line tokens seen in fewer training alerts are dropped
    U0_BELOW = 0.5       # category probability under which a threat is called U0 (fixed, not tuned)

    def __init__(self, ctx: Context, seed: int = 2026):
        self.ctx = ctx
        self.vec = DictVectorizer(sparse=False)
        self.cat = HistGradientBoostingClassifier(random_state=seed, class_weight="balanced", max_iter=300)
        self.disp = HistGradientBoostingClassifier(random_state=seed, class_weight="balanced", max_iter=300)
        self.dismiss_cutoff = 1.01  # never dismiss until calibrated
        self.dismiss_cutoff_met = False
        self.confidence_threshold = 0.99
        self.info: dict = {}

    # ---------------------------------------------------------------- training

    def fit(self, alerts, truth):
        rows = [features(a, self.ctx) for a in alerts]
        counts: dict[str, int] = {}
        for r in rows:
            for k in r:
                if k.startswith("cmd="):
                    counts[k] = counts.get(k, 0) + 1
        rare = {k for k, n in counts.items() if n < self.MIN_TOKEN_COUNT}
        rows = [{k: v for k, v in r.items() if k not in rare} for r in rows]
        X = self.vec.fit_transform(rows)  # unseen tokens are ignored at predict time
        self.cat.fit(X, [g["category"] for g in truth])
        self.disp.fit(X, [g["disposition"] for g in truth])
        return self

    def calibrate(self, alerts, truth, target_recall: float, cutoffs):
        """Pick the lowest dismiss cutoff that keeps threat recall >= target on these alerts."""
        scores = self.scores(alerts)
        y = np.array([g["disposition"] == "TP" for g in truth])
        for c in cutoffs:
            d = [x[1] for x in self.decide_all(alerts, scores, c)]
            p = np.array([x in THREAT_SIDE for x in d])
            if (y & p).sum() / max(int(y.sum()), 1) >= target_recall:
                self.dismiss_cutoff, self.dismiss_cutoff_met = c, True
                return self
        self.dismiss_cutoff, self.dismiss_cutoff_met = 1.01, False  # target unreachable: never dismiss
        return self

    # ---------------------------------------------------------------- prediction

    def scores(self, alerts):
        X = self.vec.transform([features(a, self.ctx) for a in alerts])
        return (self.disp.predict_proba(X), list(self.disp.classes_),
                self.cat.predict_proba(X), list(self.cat.classes_))

    def argmax_all(self, alerts):
        """Plain model output, no rules and no cutoff (the 'structured' approach in the experiment)."""
        pd_, dc, pc, cc = self.scores(alerts)
        return ([cc[i] for i in pc.argmax(1)], [dc[i] for i in pd_.argmax(1)], list(pd_.max(1)))

    def decide_all(self, alerts, scores=None, cutoff=None):
        pd_, dc, pc, cc = scores if scores is not None else self.scores(alerts)
        cutoff = self.dismiss_cutoff if cutoff is None else cutoff
        return [self.decide(a, dict(zip(dc, p)), dict(zip(cc, q)), cutoff) for a, p, q in zip(alerts, pd_, pc)]

    def decide(self, alert, p_disp: dict, p_cat: dict, cutoff: float):
        """Returns (category, disposition, confidence, decided_by, detail)."""
        rc, rd, rconf = rules_predict(alert, self.ctx)
        if rd == "BTP":
            return rc, rd, rconf, "rules", {}
        if alert["rule_id"] not in RULE_CATEGORY:
            return "U0", "needs_investigation", 0.0, "rules", {"unknown_rule": alert["rule_id"]}
        p_tp = float(p_disp.get("TP", 0.0))
        p_benign = 1.0 - p_tp
        top_cat = max(p_cat, key=p_cat.get)
        detail = {"p_threat": round(p_tp, 3), "dismiss_cutoff": cutoff,
                  "top_category": top_cat, "p_top_category": round(float(p_cat[top_cat]), 3)}
        if p_benign >= cutoff:
            d = max((c for c in p_disp if c != "TP"), key=p_disp.get)
            if d == "BTP":
                c = top_cat if top_cat in ("B1", "B2") else "B2"
            else:
                c = RULE_CATEGORY[alert["rule_id"]]
            return c, d, p_benign, "model", detail
        if p_cat[top_cat] < self.U0_BELOW:
            return "U0", "needs_investigation", p_tp, "model", detail
        c = top_cat if top_cat in ATTACK_CATEGORIES else RULE_CATEGORY[alert["rule_id"]]
        return c, "TP", p_tp, "model", detail

    # ---------------------------------------------------------------- persistence

    def save(self, path: Path, **info):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"format_version": FORMAT_VERSION, "vectorizer": self.vec, "category": self.cat,
                     "disposition": self.disp, "dismiss_cutoff": self.dismiss_cutoff,
                     "dismiss_cutoff_met": self.dismiss_cutoff_met,
                     "confidence_threshold": self.confidence_threshold, "info": info}, path)

    @classmethod
    def load(cls, path: Path, ctx: Context) -> "TriageModel":
        data = joblib.load(path)
        if data.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"{path}: not a triage model file (rerun scripts/triage_experiment.py)")
        m = cls(ctx)
        m.vec, m.cat, m.disp = data["vectorizer"], data["category"], data["disposition"]
        m.dismiss_cutoff, m.dismiss_cutoff_met = data["dismiss_cutoff"], data["dismiss_cutoff_met"]
        m.confidence_threshold, m.info = data["confidence_threshold"], data.get("info", {})
        return m
