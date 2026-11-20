"""System 1 Fast Local Decision Model (<500MB).

Provides sub-millisecond heuristic & statistical triage for incoming alerts.
Can fast-path high-confidence alerts (>0.85) and provide immediate prior
hypotheses to downstream System 2 deliberative multi-agent workflows.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from backend.agents.triage import extract_iocs
from backend.config import get_settings
from backend.models.schemas import Alert, TriageResult

logger = logging.getLogger("system1_decision")


class NeuralDecisionEngine:
    """Non-autoregressive Neural Decision Engine (<100M parameters) using typed primitives."""

    def __init__(self, model_id: str = "typeform/distilbert-base-uncased-mnli"):
        self.model_id = model_id
        self.tokenizer = None
        self.model = None
        self.entailment_idx = 2
        self.contradiction_idx = 0
        self.is_loaded = False
        self._try_load()

    def _try_load(self) -> bool:
        try:
            import os
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            # Attempt local offline cache load first
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=True)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id, local_files_only=True)
            self.model.eval()
            id2label = {i: l.lower() for i, l in self.model.config.id2label.items()}
            self.entailment_idx = next(i for i, l in id2label.items() if "entail" in l)
            self.contradiction_idx = next(i for i, l in id2label.items() if "contra" in l)
            self.is_loaded = True
            logger.info(f"Loaded System 1 Neural Decision Model: {self.model_id}")
            return True
        except Exception as e:
            logger.debug(f"Neural decision engine local load skipped ({e}); statistical mode active.")
            self.is_loaded = False
            return False

    def evaluate_noul(self, premise: str, hypothesis: str) -> float:
        """Evaluate a boolean decision probability P(hypothesis is true | premise)."""
        import torch
        inputs = self.tokenizer(premise, hypothesis, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            logits = self.model(**inputs).logits[0]
            ent_contra_logits = torch.stack([logits[self.contradiction_idx], logits[self.entailment_idx]])
            probs = torch.softmax(ent_contra_logits, dim=0)
            return float(probs[1].item())

    def evaluate_choice(self, premise: str, choices: Dict[str, str]) -> Dict[str, Any]:
        """Evaluate categorical choice questions over candidate hypotheses."""
        import torch
        scores = {}
        for cat_name, hyp_template in choices.items():
            inputs = self.tokenizer(premise, hyp_template, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                logits = self.model(**inputs).logits[0]
                ent_contra_logits = torch.stack([logits[self.contradiction_idx], logits[self.entailment_idx]])
                scores[cat_name] = float(torch.softmax(ent_contra_logits, dim=0)[1].item())
        exp_scores = {k: torch.exp(torch.tensor(v * 3.0)).item() for k, v in scores.items()}
        total_exp = sum(exp_scores.values()) or 1.0
        norm_scores = {k: v / total_exp for k, v in exp_scores.items()}
        best_choice = max(norm_scores.items(), key=lambda x: x[1])
        return {"selected_choice": best_choice[0], "confidence": best_choice[1]}

    def predict(self, alert: Alert) -> TriageResult:
        """Run neural decision pass on alert."""
        premise = f"Security Event: {alert.description}. Type: {alert.event_type}. User: {alert.user or 'N/A'}. Host: {alert.host or 'N/A'}."
        p_malicious = self.evaluate_noul(premise, "This event represents an active, unauthorized security threat or intrusion.")
        p_approved = self.evaluate_noul(premise, "This event represents normal, authorized IT operations or scheduled maintenance.")

        choices = {
            "brute_force": "The attacker is attempting repeated unauthorized authentication or credential spraying.",
            "malware": "Malicious code, ransomware, or living-off-the-land executable was launched.",
            "suspicious_outbound_connection": "Suspicious outbound network traffic, data exfiltration, or command and control beaconing.",
            "port_scan": "An automated network port scan or host discovery sweep is probing the network.",
            "approved_activity": "This is legitimate IT administration, scheduled vulnerability assessment, or routine maintenance.",
        }
        choice_res = self.evaluate_choice(premise, choices)
        is_tp = p_malicious > p_approved and p_malicious > 0.40
        pred_class = "likely_true_positive" if is_tp else "likely_false_positive"
        pred_cat = choice_res["selected_choice"]
        confidence = max(p_malicious, p_approved)

        severity = "high" if is_tp and confidence > 0.85 else ("medium" if is_tp else "low")
        iocs = extract_iocs(alert)

        reasoning = (
            f"System 1 Neural Decision Model (<100M params) evaluated alert: "
            f"P(threat)={p_malicious:.3f}, P(approved)={p_approved:.3f}. Category: '{pred_cat}' (Confidence: {confidence:.2f})."
        )
        return TriageResult(
            alert_id=alert.alert_id,
            classification=pred_class,
            category=pred_cat,
            severity=severity,
            confidence=round(confidence, 3),
            reasoning_summary=reasoning,
            extracted_iocs=iocs,
            required_investigations=["authentication_logs", "network_flows", "endpoint_telemetry"],
            recommended_next_step=(
                "Auto-close as benign noise." if pred_class == "likely_false_positive" and confidence >= 0.90
                else "Escalate to System 2 Multi-Agent deliberation (Log Correlation & Threat Intel)."
            ),
        )


class System1TriageModel:
    """Lightweight, sub-millisecond local decision model (<500MB)."""

    def __init__(self, model_path: str = "models/system1_triage.joblib"):
        p = Path(model_path)
        if not p.exists() and Path("locals/models/system1_triage.joblib").exists():
            p = Path("locals/models/system1_triage.joblib")
        self.model_path = p
        self.pipeline: Optional[Any] = None
        self.category_classes_: Optional[List[str]] = None
        self.is_trained = False
        self._neural_engine: Optional[NeuralDecisionEngine] = None
        
        if self.model_path.exists():
            self.load()

    @property
    def neural_engine(self) -> Optional[NeuralDecisionEngine]:
        """Lazy load neural decision engine only when explicitly requested."""
        if self._neural_engine is None:
            settings = get_settings()
            if settings.system1_architecture in ("neural", "hybrid"):
                try:
                    engine = NeuralDecisionEngine(settings.system1_neural_model_id)
                    if engine.is_loaded:
                        self._neural_engine = engine
                except Exception as e:
                    logger.debug(f"Neural engine init skipped: {e}")
        return self._neural_engine

    def _extract_features(self, alert: Alert) -> str:
        """Create dense text representations for TF-IDF feature representation."""
        metadata = alert.metadata or {}
        meta_str = " ".join(f"{k}:{v}" for k, v in metadata.items() if not k.startswith("ground_truth"))
        return (
            f"event:{alert.event_type} host:{alert.host or ''} user:{alert.user or ''} "
            f"failed:{alert.failed_attempts or 0} {alert.description} {meta_str}"
        )

    def train_on_corpus(self, train_data_path: str = "data/soc_alerts_train.json") -> Dict[str, float]:
        """Train the System 1 classifier on normalized SOC training alerts."""
        path = Path(train_data_path)
        if not path.exists() and Path("locals/data/soc_alerts_train.json").exists():
            path = Path("locals/data/soc_alerts_train.json")
        if not path.exists():
            raise FileNotFoundError(f"Training corpus not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            records = json.load(f)

        texts: List[str] = []
        labels_cat: List[str] = []
        labels_class: List[str] = []
        labels_sev: List[str] = []

        for r in records:
            alert = Alert(**r)
            texts.append(self._extract_features(alert))
            labels_cat.append(r["metadata"]["ground_truth_category"])
            labels_class.append(r["metadata"]["ground_truth_classification"])
            labels_sev.append(r["metadata"]["ground_truth_severity"])

        # Train Category Classifier
        cat_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=3000)),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", C=2.0)),
        ])
        cat_pipeline.fit(texts, labels_cat)

        # Train Classification Pipeline
        class_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=3000)),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", C=2.0)),
        ])
        class_pipeline.fit(texts, labels_class)

        # Train Severity Pipeline
        sev_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=3000)),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", C=2.0)),
        ])
        sev_pipeline.fit(texts, labels_sev)

        self.pipeline = {
            "category": cat_pipeline,
            "classification": class_pipeline,
            "severity": sev_pipeline,
        }
        self.is_trained = True
        self.save()

        # Score accuracy on training set
        train_cat_acc = float(cat_pipeline.score(texts, labels_cat))
        train_class_acc = float(class_pipeline.score(texts, labels_class))
        return {
            "train_category_accuracy": train_cat_acc,
            "train_classification_accuracy": train_class_acc,
            "sample_count": len(texts),
        }

    def save(self) -> None:
        """Persist model bundle to disk (<15MB)."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path, compress=3)

    def load(self) -> None:
        """Load trained model bundle into memory."""
        try:
            self.pipeline = joblib.load(self.model_path)
            self.is_trained = True
        except Exception as e:
            logger.warning(f"Could not load System 1 model from {self.model_path}: {e}")
            self.is_trained = False

    def predict(self, alert: Alert, force_architecture: Optional[str] = None) -> TriageResult:
        """Fast triage decision inference (Neural <100M or Statistical)."""
        settings = get_settings()
        arch = force_architecture or settings.system1_architecture

        if arch in ("neural", "hybrid") and self.neural_engine and self.neural_engine.is_loaded:
            try:
                return self.neural_engine.predict(alert)
            except Exception as e:
                logger.warning(f"Neural decision pass failed ({e}); falling back to statistical.")

        if not self.is_trained or self.pipeline is None:
            # Lazy auto-train if dataset exists
            train_path = Path("data/soc_alerts_train.json")
            if not train_path.exists() and Path("locals/data/soc_alerts_train.json").exists():
                train_path = Path("locals/data/soc_alerts_train.json")
            if train_path.exists():
                self.train_on_corpus(str(train_path))
            else:
                raise RuntimeError("System 1 model is not trained and training data is unavailable.")

        text = self._extract_features(alert)
        iocs = extract_iocs(alert)

        cat_pipe = self.pipeline["category"]
        class_pipe = self.pipeline["classification"]
        sev_pipe = self.pipeline["severity"]

        pred_cat = cat_pipe.predict([text])[0]
        cat_probs = cat_pipe.predict_proba([text])[0]
        confidence = float(np.max(cat_probs))

        pred_class = class_pipe.predict([text])[0]
        pred_sev = sev_pipe.predict([text])[0]

        # Determine required investigations based on predicted category
        investigation_map = {
            "brute_force": ["authentication_logs", "source_ip_reputation", "user_access_history"],
            "port_scan": ["firewall_logs", "network_flows", "source_ip_reputation"],
            "malware": ["edr_telemetry", "file_hash_reputation", "process_tree_analysis"],
            "suspicious_outbound_connection": ["egress_proxy_logs", "dns_queries", "destination_reputation"],
            "approved_activity": ["change_management_tickets", "asset_inventory"],
            "user_typo": ["recent_auth_attempts"],
            "unknown_anomaly": ["cross_source_timeline", "asset_baseline"],
        }
        investigations = investigation_map.get(pred_cat, ["security_logs", "asset_inventory"])

        reasoning = (
            f"System 1 Fast Decision Model classified alert as '{pred_cat}' "
            f"with severity '{pred_sev}' (confidence: {confidence:.2f}) based on statistical feature match."
        )

        return TriageResult(
            alert_id=alert.alert_id,
            classification=pred_class,
            category=pred_cat,
            severity=pred_sev,
            confidence=round(confidence, 3),
            reasoning_summary=reasoning,
            extracted_iocs=iocs,
            required_investigations=investigations,
            recommended_next_step=(
                "Auto-close as benign after change verification."
                if pred_class == "likely_false_positive"
                else "Proceed to multi-agent correlation and threat intelligence investigation."
            ),
        )


system1_model = System1TriageModel()
