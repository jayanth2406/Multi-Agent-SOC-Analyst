"""Triage features, rules, provisional severity and routing.

Everything here uses only what triage is allowed to see at alert time:
the alert itself and the asset inventory. No threat intel, no log queries,
and never the ground-truth file. The Triage agent and scripts/triage_experiment.py
both use this module, so the experiment measures exactly what the agent does.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import math
import re
from backend.triage.inventory import Inventory  # noqa: F401  (re-exported)
from backend.triage.rubric import TIERS, investigation_depth, severity

# The attack category each detection rule claims. BTP alerts become B1/B2 instead.
RULE_CATEGORY = {
    "R-NET-SCAN": "C1", "R-NET-BRUTE": "C2", "R-NET-EXPLOIT": "C4", "R-NET-DOS": "C7",
    "R-NET-C2": "C6", "R-NET-MALWARE": "C5", "R-EDR-PROC": "C5",
    "R-AUTH-FAIL": "C2", "R-AUTH-LOCK": "C2", "R-AUTH-REMOTE": "C3",
}

# Provisional attack stage triage assumes for a threat of each category.
# Triage cannot see whether an exploit succeeded, so it uses the cautious default.
CATEGORY_STAGE = {"C1": 1, "C2": 1, "C3": 3, "C4": 1, "C5": 3, "C6": 4, "C7": 2,
                  "B1": 0, "B2": 0, "U0": 2}

DAYS = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}


UNKNOWN_ASSET_TIER = "High"  # an asset missing from the inventory is treated cautiously


def parse_ts(alert) -> dt.datetime:
    """The alert time in UTC, without tzinfo. Accepts '...Z', '+00:00' offsets and naive times (taken as UTC)."""
    ts = alert["timestamp"]
    if isinstance(ts, dt.datetime):
        t = ts
    else:
        t = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    if t.tzinfo is not None:
        t = t.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return t


def in_window(ts: dt.datetime, window: dict) -> bool:
    """True if ts falls inside an inventory window (handles windows that cross midnight)."""
    sh, sm = map(int, window["start"].split(":"))
    eh, em = map(int, window["end"].split(":"))
    start, end = sh * 60 + sm, eh * 60 + em
    minute = ts.hour * 60 + ts.minute

    def day_ok(weekday):
        d = window["day"]
        return d == "daily" or (d == "weekdays" and weekday < 5) or DAYS.get(d) == weekday

    if end > start:
        return day_ok(ts.weekday()) and start <= minute < end
    # crosses midnight: the window's day covers the evening, the next day the early hours
    return (day_ok(ts.weekday()) and minute >= start) or (day_ok((ts.weekday() - 1) % 7) and minute < end)


class Context:
    """Inventory lookups used by both the rules and the features."""

    def __init__(self, inventory: Inventory):
        self.inv = inventory
        self.ip_to_host = {h["ip"]: name for name, h in inventory.hosts.items()}

    def internal(self, ip) -> bool:
        if not ip:
            return False
        return any(ipaddress.ip_address(ip) in n for n in self.inv.networks)

    def host_of(self, ip):
        return self.ip_to_host.get(ip)

    def users(self, alert):
        return alert.get("users") or ([alert["user"]] if alert.get("user") else [])

    def approved_match(self, alert):
        """The id of the approved activity this alert fits, or None."""
        ts = parse_ts(alert)
        src, host, users = alert.get("src_ip"), alert.get("host"), self.users(alert)
        for aid, a in self.inv.approved.items():
            if not in_window(ts, a["window"]):
                continue
            actor = False
            if a.get("actor_ip") and src == a["actor_ip"]:
                actor = True
            if a.get("actor_host") and src == self.inv.ip(a["actor_host"]):
                actor = True
            if a.get("actor_host") and host == a["actor_host"] and not a.get("targets"):
                actor = True
            if a.get("actor_accounts") and any(u in a["actor_accounts"] for u in users):
                actor = True
            if not actor:
                continue
            if a.get("destination_ip"):
                if alert.get("dst_ip") == a["destination_ip"]:
                    return aid
                continue
            targets = a.get("targets")
            if not targets:
                return aid
            for t in targets:
                if "/" in t:
                    ip = alert.get("dst_ip")
                    if ip and ipaddress.ip_address(ip) in ipaddress.ip_network(t):
                        return aid
                elif t == host:
                    return aid
        return None

    def user_error(self, alert):
        """Heuristic for B2: a single user's few failures from their own machine or the VPN."""
        if alert["rule_id"] not in ("R-AUTH-FAIL", "R-AUTH-LOCK"):
            return False
        users = self.users(alert)
        obs = alert.get("observables", {})
        if len(users) != 1 or (obs.get("failures") or 99) > 6:
            return False
        src_host = self.host_of(alert.get("src_ip"))
        own_machine = src_host is not None and self.inv.owner(src_host) == users[0]
        via_vpn = alert.get("host") == "vpn-01" and self.inv.accounts.get(users[0], {}).get("type") == "user"
        return own_machine or via_vpn

    def tier(self, alert) -> str:
        try:
            return self.inv.tier(alert.get("host"), self.users(alert))
        except ValueError:
            return UNKNOWN_ASSET_TIER

    def in_inventory(self, alert) -> bool:
        return alert.get("host") in self.inv.hosts or any(u in self.inv.accounts for u in self.users(alert))


# ----------------------------------------------------------------------------- rules baseline

def rules_predict(alert, ctx: Context):
    """Approach A. Returns (category, disposition, confidence)."""
    if ctx.approved_match(alert):
        return "B1", "BTP", 0.95
    if ctx.user_error(alert):
        return "B2", "BTP", 0.8
    if alert["rule_id"] not in RULE_CATEGORY:
        return "U0", "needs_investigation", 0.0
    # Rules cannot tell a false positive from a real attack: treat it as real.
    return RULE_CATEGORY[alert["rule_id"]], "TP", 0.6


# ----------------------------------------------------------------------------- features

def _log(x):
    return math.log1p(max(float(x), 0.0)) if x is not None else -1.0


def features(alert, ctx: Context) -> dict:
    """Approach B: one flat dict of structured features (DictVectorizer one-hot encodes strings)."""
    obs = alert.get("observables", {})
    ts = parse_ts(alert)
    users = ctx.users(alert)
    src, dst = alert.get("src_ip"), alert.get("dst_ip")
    src_host, host = ctx.host_of(src), alert.get("host")
    inv = ctx.inv
    user_types = sorted({inv.accounts.get(u, {}).get("type", "unknown") for u in users}) or ["none"]
    f = {
        "rule": alert["rule_id"], "source_system": alert.get("source_system", ""),
        "protocol": alert.get("protocol", "none"), "service": alert.get("service") or "none",
        "dst_port": str(alert.get("dst_port", "none")),
        "auth": obs.get("auth", "none"), "event": obs.get("event", "none"),
        "process": alert.get("process", "none"),
        "log_packets": _log(obs.get("packets")), "log_bytes_out": _log(obs.get("bytes_out")),
        "log_bytes_in": _log(obs.get("bytes_in")), "log_duration": _log(obs.get("duration_s")),
        "log_packet_rate": _log(obs.get("packet_rate")),
        "failures": float(obs.get("failures", -1) if obs.get("failures") is not None else -1),
        "minutes": float(obs.get("minutes", -1) if obs.get("minutes") is not None else -1),
        "n_hosts": float(obs.get("n_hosts", 0) or 0), "n_users": float(len(users)),
        "success_after": float(bool(obs.get("success_after"))), "lockout": float(bool(obs.get("lockout"))),
        "src_internal": float(ctx.internal(src)), "dst_internal": float(ctx.internal(dst)) if dst else -1.0,
        "src_role": inv.hosts[src_host]["role"] if src_host else ("external" if src else "none"),
        "host_role": inv.hosts[host]["role"] if host in inv.hosts else "none",
        "host_tier": float(TIERS.index(inv.hosts[host]["tier"])) if host in inv.hosts else -1.0,
        "in_inventory": float(ctx.in_inventory(alert)),
        "asset_tier": float(TIERS.index(ctx.tier(alert))),
        "user_type": "+".join(user_types),
        "user_owns_src": float(bool(src_host and users and inv.owner(src_host) == users[0])),
        "approved_match": ctx.approved_match(alert) or "none",
        "user_error_heuristic": float(ctx.user_error(alert)),
        "hour": float(ts.hour), "weekday": float(ts.weekday()),
        "business_hours": float(ts.weekday() < 5 and 9 <= ts.hour < 18),
    }
    for tok in cmd_tokens(alert.get("command_line")):
        f[f"cmd={tok}"] = 1.0
    return f


_TOKEN = re.compile(r"[a-z_./-][a-z0-9_./-]{1,60}")
_HEXISH = re.compile(r"x?[0-9a-f]+")  # hex values and addresses, not words
_BORING = {"name", "type", "value", "const", "char", "char*", "int", "unsigned", "long", "void", "flags", "mode"}


def cmd_tokens(command_line) -> set[str]:
    """Words and paths from a command line (EDR alerts), without numbers and boilerplate."""
    if not command_line:
        return set()
    toks = set(_TOKEN.findall(str(command_line).lower()))
    return {t.strip("./") or t for t in toks if t not in _BORING and not _HEXISH.fullmatch(t)}


# ----------------------------------------------------------------------------- severity

def provisional(alert, category, disposition, ctx: Context):
    """Provisional stage, severity and investigation depth, the way triage would compute them."""
    if disposition not in ("TP", "needs_investigation"):
        stage = 0
    else:
        stage = CATEGORY_STAGE.get(category, 2)
        if category == "C3" and (alert.get("observables", {}).get("n_hosts") or 1) > 1:
            stage = 4
    spread = stage >= 2 and (alert.get("observables", {}).get("n_hosts") or 1) > 1
    tier = ctx.tier(alert)
    level = severity(stage, tier, spread=spread)
    return stage, tier, level


# ----------------------------------------------------------------------------- routing

def route_one(alert, category, disposition, confidence, ctx: Context, threshold: float):
    """Provisional severity and light/full routing for one alert.

    Applies the stateless safeguards from the requirements: 2 (High or Critical
    asset), 3 (category U0) and 4 (confidence below the threshold). Safeguard 1
    (malicious IOC) needs threat intel and safeguard 5 (repeat source) needs alert
    history; the Triage agent adds those.
    Returns (stage, tier, level, depth, safeguards_fired).
    """
    stage, tier, level = provisional(alert, category, disposition, ctx)
    depth = investigation_depth(level)
    fired = []
    if tier in ("High", "Critical"):
        fired.append("asset_tier")
    if category == "U0":
        fired.append("unclassified")
    if confidence < threshold:
        fired.append("low_confidence")
    if depth == "light" and fired:
        depth = "full"
    return stage, tier, level, depth, fired
