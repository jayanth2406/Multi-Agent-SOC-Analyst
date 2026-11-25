"""Triage agent v1: requirements FR-TRI-1 to FR-TRI-7.

For each alert it decides the category (10-class taxonomy), the disposition
(TP / BTP / FP / needs_investigation) with a confidence, the provisional stage
and severity from the rubric, light or full investigation with the safeguards,
the IOCs, the log sources a full investigation should query, and a short
reasoning summary.

How it decides is in backend/triage/model.py: rules for approved activity and
user errors, then the trained model, which dismisses an alert only when it is
confident. With no model file it falls back to the rules alone (FR-TRI-7), which
treat every alert the rules cannot clear as a threat and route it to full
investigation.

The older keyword agent in backend/agents/triage.py still serves the LangGraph
pipeline; moving the pipeline onto this agent is Semester 8 orchestration work.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import re
import threading
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path

from backend.config import Settings, get_settings
from backend.models.schemas import IndicatorSet, SocAlert, TriageDecision
from backend.triage.features import RULE_CATEGORY, Context, parse_ts, route_one, rules_predict
from backend.triage.inventory import Inventory
from backend.triage.model import TriageModel
from backend.triage.rubric import CATEGORIES

logger = logging.getLogger("triage_agent")
ROOT = Path(__file__).resolve().parent.parent.parent

LOG_SOURCES = {"C1": ["network"], "C2": ["auth", "network"], "C3": ["auth", "endpoint"],
               "C4": ["network", "endpoint"], "C5": ["endpoint", "network"], "C6": ["network", "endpoint"],
               "C7": ["network"], "U0": ["network", "auth", "endpoint"]}
STAGE_NAMES = {0: "no threat", 1: "attempt", 2: "disruption or partial success", 3: "compromise",
               4: "post-compromise"}
SAFEGUARD_TEXT = {"asset_tier": "the asset is High or Critical tier", "unclassified": "the category is unclear",
                  "low_confidence": "confidence is below the threshold",
                  "repeat_source": "this source or account has raised many alerts recently"}

_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)
_FILE_EXT = {"exe", "dll", "sys", "sh", "py", "ps1", "bat", "cmd", "vbs", "js", "txt", "log", "dmp", "zip",
             "gz", "tar", "conf", "cfg", "ini", "json", "xml", "yaml", "yml", "so", "bin", "tmp", "dat", "db"}
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


class TriageAgent:
    def __init__(self, inventory_path: Path, model_path: Path | None = None,
                 repeat_threshold: int = 5, repeat_window_hours: int = 24):
        self.ctx = Context(Inventory(inventory_path))
        self.model: TriageModel | None = None
        self.model_version: str | None = None
        if model_path is not None and Path(model_path).exists():
            try:
                self.model = TriageModel.load(model_path, self.ctx)
                self.model_version = f"{Path(model_path).name} (trained on {self.model.info.get('n_train')} alerts)"
            except Exception as e:  # a broken or old model file must not stop triage
                logger.warning("could not load %s (%s); using rules only", model_path, e)
        elif model_path is not None:
            logger.warning("no triage model at %s; using rules only (run scripts/triage_experiment.py)", model_path)
        self.repeat_threshold = repeat_threshold
        self.repeat_window = dt.timedelta(hours=repeat_window_hours)
        self._seen: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- public

    def triage(self, alert: SocAlert) -> TriageDecision:
        a = alert.model_dump(mode="json", exclude_none=True)
        if self.model is not None:
            p_disp, dc, p_cat, cc = self.model.scores([a])
            category, disposition, confidence, decided_by, detail = self.model.decide(
                a, dict(zip(dc, p_disp[0])), dict(zip(cc, p_cat[0])), self.model.dismiss_cutoff)
            threshold = self.model.confidence_threshold
        else:
            category, disposition, confidence = rules_predict(a, self.ctx)
            decided_by = "rules" if disposition == "BTP" else "rules_only_fallback"
            detail, threshold = {}, 0.99

        stage, tier, level, depth, fired = route_one(a, category, disposition, confidence, self.ctx, threshold)
        if self._repeat_source(a):
            fired.append("repeat_source")
            depth = "full"

        return TriageDecision(
            alert_id=a["alert_id"], category=category, category_name=CATEGORIES[category],
            disposition=disposition, confidence=round(float(confidence), 3), stage=stage, asset_tier=tier,
            severity=level, investigation=depth, safeguards_fired=fired,
            safeguards_not_checked=["malicious_ioc (needs threat intelligence, Semester 8)"],
            indicators=self._indicators(a), log_sources=self._log_sources(a, category),
            reasoning_summary=self._reasoning(a, category, disposition, confidence, decided_by, detail,
                                              stage, tier, level, depth, fired, threshold),
            decided_by=decided_by, model_version=self.model_version, normalised_alert=a,
        )

    # ---------------------------------------------------------------- helpers

    def _repeat_source(self, a) -> bool:
        """Safeguard 5: the same source IP or account in at least N alerts within the window."""
        now = parse_ts(a)
        keys = [f"ip:{a['src_ip']}"] if a.get("src_ip") else []
        keys += [f"user:{u}" for u in self.ctx.users(a)]
        fired = False
        with self._lock:
            for k in keys:
                q = self._seen[k]
                q.append(now)
                while q and now - q[0] > self.repeat_window:
                    q.popleft()
                fired |= len(q) >= self.repeat_threshold
        return fired

    def _indicators(self, a) -> IndicatorSet:
        ext, internal = [], []
        for ip in (a.get("src_ip"), a.get("dst_ip")):
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            (internal if self.ctx.internal(ip) else ext).append(ip)
        text = f"{a.get('description', '')} {a.get('command_line', '')}"
        domains = sorted({m.group(0).lower() for m in _DOMAIN.finditer(text)
                          if m.group(1).lower() not in _FILE_EXT and not m.group(0).replace(".", "").isdigit()})
        hashes = sorted({h.lower() for h in _HASH.findall(f"{a.get('file_hash', '')} {a.get('command_line', '')}")})
        dedup = lambda xs: list(dict.fromkeys(x for x in xs if x))  # noqa: E731
        return IndicatorSet(external_ips=dedup(ext), internal_ips=dedup(internal), domains=domains,
                            file_hashes=hashes, hosts=dedup([a.get("host")]), users=dedup(self.ctx.users(a)),
                            processes=dedup([a.get("process")]))

    @staticmethod
    def _log_sources(a, category):
        if category in ("B1", "B2"):
            category = RULE_CATEGORY.get(a["rule_id"], "U0")
        return LOG_SOURCES.get(category, LOG_SOURCES["U0"])

    def _reasoning(self, a, category, disposition, confidence, decided_by, detail, stage, tier, level, depth,
                   fired, threshold) -> str:
        host = a.get("host") or "an unknown host"
        parts = [f"{a.get('rule_name') or a['rule_id']} on {host} ({tier} tier"
                 + ("" if self.ctx.in_inventory(a) else ", not in the asset inventory") + ")."]
        if decided_by == "rules" and category == "B1":
            act = self.ctx.inv.approved[self.ctx.approved_match(a)]
            parts.append(f"Matches approved activity '{act['id']}' ({act['description']}): "
                         "actor, target and time window all fit.")
        elif decided_by == "rules" and category == "B2":
            parts.append("One account with a few failed logins from its own machine or the VPN: "
                         "consistent with a user error.")
        elif "unknown_rule" in detail:
            parts.append(f"Rule {detail['unknown_rule']} is not in the taxonomy, so the category is unclear.")
        elif decided_by == "rules_only_fallback":
            parts.append("No trained model is loaded; the rules cannot clear this alert, so it is treated as a threat.")
        elif disposition in ("BTP", "FP"):
            parts.append(f"The model rates it {1 - detail['p_threat']:.0%} likely not a threat, above the "
                         f"{detail['dismiss_cutoff']:.0%} dismiss cutoff"
                         + (": looks like a false positive." if disposition == "FP" else ": looks like benign activity."))
        elif category == "U0":
            parts.append(f"The model rates it {detail['p_threat']:.0%} likely a threat but is unsure of the category "
                         f"(best guess {detail['top_category']} at {detail['p_top_category']:.0%}).")
        else:
            parts.append(f"The model rates it {detail['p_threat']:.0%} likely a real threat.")
        if disposition in ("TP", "needs_investigation"):
            parts.append(f"Provisional stage {stage} ({STAGE_NAMES[stage]}) on a {tier} asset gives {level} severity.")
        else:
            parts.append("Not a threat, so severity is Informational.")
        if depth == "full" and fired:
            parts.append("Full investigation because " + "; ".join(SAFEGUARD_TEXT[f] for f in fired) + ".")
        else:
            parts.append(f"{depth.capitalize()} investigation.")
        return " ".join(parts)


@lru_cache
def get_triage_agent() -> TriageAgent:
    s: Settings = get_settings()
    return TriageAgent(_resolve(s.asset_inventory_path), _resolve(s.triage_model_path),
                       s.repeat_source_threshold, s.repeat_source_window_hours)
