"""Build the labelled proof-of-concept alert set (requirements DR-4 to DR-8).

Usage:
    python scripts/build_poc_alerts.py --raw-dir data/raw --out data/poc_alerts

Inputs (put the official files under --raw-dir; nothing is downloaded here):
    unsw_nb15/*.csv     UNSW-NB15 CSVs with a header row (training/testing-set format)
    cicids2017/*.csv    CICIDS2017 CSVs (MachineLearningCVE or GeneratedLabelledFlows format)
    beth/*.csv          BETH labelled process-event CSVs
    lanl/redteam.txt[.gz]  optional: LANL red-team events (time,user@domain,src,dst)

Outputs (in --out):
    alerts_{train,val,test}.jsonl        what the agents see; no labels or provenance
    ground_truth_{train,val,test}.jsonl  the answer key, keyed by alert_id
    overlay.jsonl                        every remapping of a dataset value (DR-3)
    manifest.json                        seed, input checksums, counts, warnings

Rules this script enforces:
  * TP alerts come from rows the dataset itself labels as attacks; FP alerts come
    from deliberately loose rules run over rows the dataset labels benign; BTP
    alerts are scripted authorised activity or user error (DR-4).
  * Dataset values are never edited. Hosts, users, IPs and times are mapped into
    one fictional organisation through the overlay table (DR-3). External IPs
    come from the IETF documentation ranges for every disposition alike, so an
    IP range can never give away the label.
  * Every rule that produces TP alerts also produces BTP or FP alerts, so a rule
    name alone never gives away the disposition.
  * Splits are made by source group, per (category, disposition), and each split
    uses its own wording variants, so no description is shared across splits (DR-6).
  * Alert records hold no label, dataset or "approved" fields (DR-7).
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.triage.inventory import Inventory  # noqa: E402,F401  (re-exported for older imports)
from backend.triage.rubric import investigation_depth, severity  # noqa: E402

GENERATOR_VERSION = "0.2.0"
PERIOD_START = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)  # a Monday
PERIOD_DAYS = 14
SPLIT_RATIOS = (("train", 0.6), ("val", 0.2), ("test", 0.2))
SPLIT_VARIANTS = {"train": (0, 1, 2, 3, 4, 5), "val": (6, 7), "test": (8, 9)}
FIXTURE_MARKER = "FIXTURE_NOT_REAL_DATA"
INTERNAL_SOURCE_SHARE = 0.25  # share of inbound TP/FP alerts that come from an internal host
SERVICE_PORTS = {"http": 80, "https": 443, "ssh": 22, "ftp": 21, "ftp-data": 20, "smtp": 25,
                 "dns": 53, "pop3": 110, "snmp": 161, "ssl": 443, "irc": 6667, "radius": 1812, "dhcp": 67}
PORT_SERVICES = {v: k for k, v in SERVICE_PORTS.items()}


# --------------------------------------------------------------------------- helpers

def hnum(*parts) -> int:
    """Stable hash of the parts, as a non-negative int."""
    return int(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:15], 16)


def pick(seq, *key):
    return seq[hnum(*key) % len(seq)]


def frac(*key) -> float:
    return (hnum(*key) % 10_000) / 10_000


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def num(x, default=0.0) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return default
    return default if np.isnan(v) or np.isinf(v) else v


EXTERNAL_POOL = [f"198.51.100.{i}" for i in range(1, 255)] + \
                [f"203.0.113.{i}" for i in range(1, 255) if i != 50]  # .50 is the offsite backup provider
EXTERNAL_POOL.remove("198.51.100.77")  # the approved external penetration tester (see the inventory)


def external_ip(*key) -> str:
    return pick(EXTERNAL_POOL, "ext", *key)


# --------------------------------------------------------------------------- loading

MAX_BENIGN_PER_FILE = 50_000  # benign rows kept per file; attack rows are always all kept


def keep_rows(df: pd.DataFrame, is_benign: pd.Series) -> list[tuple[int, dict]]:
    """All attack rows plus a fixed sample of benign rows, keyed by original row number."""
    benign = df[is_benign]
    if len(benign) > MAX_BENIGN_PER_FILE:
        benign = benign.sample(MAX_BENIGN_PER_FILE, random_state=0)
    kept = pd.concat([df[~is_benign], benign]).sort_index()
    return list(zip(kept.index.tolist(), kept.to_dict("records")))


def _read_csvs(folder: Path, wanted: dict[str, str]):
    """Yield (file, dataframe) with normalised column names; only `wanted` columns kept."""
    for path in sorted(folder.glob("*.csv")):
        head = pd.read_csv(path, nrows=0)
        mapping = {}
        for col in head.columns:
            key = col.strip().lower()
            if key in wanted:
                mapping[col] = wanted[key]
        df = pd.read_csv(path, usecols=list(mapping), low_memory=False, encoding_errors="replace")
        df = df.rename(columns=mapping)
        yield path, df


def load_unsw(folder: Path, inputs: list):
    wanted = {"srcip": "srcip", "dstip": "dstip", "dsport": "dsport", "proto": "proto", "service": "service",
              "state": "state", "dur": "dur", "sbytes": "sbytes", "dbytes": "dbytes", "spkts": "spkts",
              "dpkts": "dpkts", "rate": "rate", "stime": "stime", "attack_cat": "attack_cat", "label": "label"}
    out = []
    for path, df in _read_csvs(folder, wanted):
        if "attack_cat" not in df or "label" not in df:
            raise SystemExit(f"{path}: not a UNSW-NB15 CSV with attack_cat and label columns")
        inputs.append({"dataset": "UNSW-NB15", "file": path.name, "sha256": sha256_file(path), "rows": len(df)})
        df["attack_cat"] = df["attack_cat"].fillna("Normal").astype(str).str.strip().replace(
            {"Backdoors": "Backdoor", "": "Normal"})
        for i, r in keep_rows(df, df["label"].fillna(0).astype(float) == 0):
            service = str(r.get("service", "-")).strip()
            service = None if service in ("-", "", "nan") else service
            dur = num(r.get("dur"))
            spk, dpk = num(r.get("spkts")), num(r.get("dpkts"))
            port = int(num(r.get("dsport"), -1)) if "dsport" in r else -1
            src, dst = r.get("srcip"), r.get("dstip")
            out.append({
                "dataset": "UNSW-NB15", "file": path.name, "row": i,
                "proto": str(r.get("proto", "tcp")), "service": service,
                "dst_port": port if port >= 0 else SERVICE_PORTS.get(service or ""),
                "dur": dur, "bytes_out": int(num(r.get("sbytes"))), "bytes_in": int(num(r.get("dbytes"))),
                "pkts": int(spk + dpk),
                "pkt_rate": num(r.get("rate"), (spk + dpk) / dur if dur > 0 else spk + dpk),
                "raw_label": r["attack_cat"], "attack": int(num(r.get("label"))) == 1,
                "orig_src": src, "orig_dst": dst,
                # one group per attacker/victim pair per minute: close to one session
                "group": f"unsw|{src}|{dst}|{int(num(r.get('stime'))) // 60}" if src and dst
                else f"unsw|{path.name}|{i // 20}",
            })
    return out


def _cic_label(x: str) -> str:
    x = str(x).replace("�", "-").replace("–", "-").strip()
    return " ".join(x.split())


def load_cicids(folder: Path, inputs: list):
    wanted = {"source ip": "src", "destination ip": "dst", "destination port": "dport", "protocol": "proto",
              "flow duration": "dur_us", "total fwd packets": "fpk", "total backward packets": "bpk",
              "total length of fwd packets": "fby", "total length of bwd packets": "bby",
              "flow packets/s": "rate", "label": "label"}
    out = []
    for path, df in _read_csvs(folder, wanted):
        if "label" not in df:
            raise SystemExit(f"{path}: not a CICIDS2017 CSV with a Label column")
        inputs.append({"dataset": "CICIDS2017", "file": path.name, "sha256": sha256_file(path), "rows": len(df)})
        df["label"] = df["label"].map(_cic_label)
        for i, r in keep_rows(df, df["label"] == "BENIGN"):
            label = r["label"]
            port = int(num(r.get("dport"), -1))
            proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(int(num(r.get("proto"), 6)), "tcp")
            src, dst = r.get("src"), r.get("dst")
            out.append({
                "dataset": "CICIDS2017", "file": path.name, "row": i,
                "proto": proto, "service": PORT_SERVICES.get(port), "dst_port": port if port >= 0 else None,
                "dur": num(r.get("dur_us")) / 1e6, "bytes_out": int(num(r.get("fby"))),
                "bytes_in": int(num(r.get("bby"))), "pkts": int(num(r.get("fpk")) + num(r.get("bpk"))),
                "pkt_rate": num(r.get("rate")), "raw_label": label, "attack": label != "BENIGN",
                "orig_src": src, "orig_dst": dst,
                "group": f"cic|{src}|{dst}" if isinstance(src, str) and isinstance(dst, str)
                else f"cic|{path.name}|{i // 20}",
            })
    return out


def load_beth(folder: Path, inputs: list):
    wanted = {"timestamp": "ts", "processid": "pid", "parentprocessid": "ppid", "userid": "uid",
              "processname": "process", "hostname": "host", "eventname": "event", "args": "args",
              "returnvalue": "ret", "sus": "sus", "evil": "evil"}
    out = []
    for path, df in _read_csvs(folder, wanted):
        if "sus" not in df or "evil" not in df:
            raise SystemExit(f"{path}: not a BETH CSV with sus and evil columns")
        inputs.append({"dataset": "BETH", "file": path.name, "sha256": sha256_file(path), "rows": len(df)})
        for i, r in keep_rows(df, df["sus"].fillna(0).astype(float) == 0):
            args = str(r.get("args", ""))
            out.append({
                "dataset": "BETH", "file": path.name, "row": i,
                "process": str(r.get("process", "")).strip(), "event": str(r.get("event", "")).strip(),
                "args": args[:160], "uid": r.get("uid"), "pid": r.get("pid"),
                "sus": int(num(r.get("sus"))), "evil": int(num(r.get("evil"))),
                "raw_label": f"sus={int(num(r.get('sus')))},evil={int(num(r.get('evil')))}",
                "attack": int(num(r.get("evil"))) == 1,
                "orig_host": r.get("host"), "orig_ts": r.get("ts"),
                "group": f"beth|{path.name}|{r.get('host')}|{r.get('pid')}",
            })
    return out


def load_lanl_redteam(folder: Path, inputs: list):
    out = []
    for name in ("redteam.txt", "redteam.txt.gz"):
        path = folder / name
        if not path.exists():
            continue
        inputs.append({"dataset": "LANL", "file": path.name, "sha256": sha256_file(path)})
        opener = gzip.open if name.endswith(".gz") else open
        with opener(path, "rt") as f:
            for i, line in enumerate(f):
                parts = line.strip().split(",")
                if len(parts) != 4:
                    continue
                t, user, src, dst = parts
                out.append({"dataset": "LANL", "file": path.name, "row": i, "orig_ts": t,
                            "orig_user": user, "orig_src": src, "orig_dst": dst, "raw_label": "redteam",
                            "attack": True, "group": f"lanl|{user}"})
        inputs[-1]["rows"] = len(out)
    return out


# --------------------------------------------------------------------------- inventory

# --------------------------------------------------------------------------- rules and wording

RULES = {
    "R-NET-SCAN": ("Port scan detected", "network_ids"),
    "R-NET-BRUTE": ("Brute force against a network service", "network_ids"),
    "R-NET-EXPLOIT": ("Possible exploit or web attack", "network_ids"),
    "R-NET-DOS": ("Possible denial of service", "network_ids"),
    "R-NET-C2": ("Suspicious outbound communication", "network_ids"),
    "R-NET-MALWARE": ("Malware traffic pattern", "network_ids"),
    "R-EDR-PROC": ("Suspicious process execution", "edr"),
    "R-AUTH-FAIL": ("Multiple failed logins", "auth_monitor"),
    "R-AUTH-LOCK": ("Account lockout", "auth_monitor"),
    "R-AUTH-REMOTE": ("Suspicious remote logon", "auth_monitor"),
}

# Ten wording variants per rule: train uses 0-5, val uses 6-7, test uses 8-9.
TEMPLATES = {
    "R-NET-SCAN": [
        "Host {src_ip} probed {host} ({dst_ip}) on {svc}: {pkts} packets in {dur}s.",
        "Scanning behaviour from {src_ip} toward {dst_ip}; {pkts} packets observed against {svc}.",
        "{src_ip} sent {pkts} probe packets to {host} over {proto}, service {svc}.",
        "Port sweep suspected: {src_ip} touched {host} {svc} with {pkts} packets ({bytes_out} bytes).",
        "Recon activity logged for {dst_ip}. Origin {src_ip}, protocol {proto}, {dur}s of probing.",
        "Many short connections from {src_ip} to {host}; {svc} targeted, {pkts} packets total.",
        "Network IDS saw a reconnaissance pattern: source {src_ip}, target {dst_ip} ({host}), {svc}, {dur}s.",
        "Probe traffic hit {host} from {src_ip} - {pkts} packets, {proto}/{svc}, {bytes_in} bytes answered.",
        "Possible service discovery against {host}: {src_ip} -> {dst_ip}, {proto}/{svc}, {pkts} pkts.",
        "Enumeration attempt? {src_ip} kept knocking on {svc} at {dst_ip} for {dur} seconds.",
    ],
    "R-NET-BRUTE": [
        "Repeated connection attempts from {src_ip} to {svc} on {host} ({dst_ip}): {pkts} packets in {dur}s.",
        "{src_ip} is hammering {svc} on {dst_ip}; {pkts} packets, {bytes_out} bytes sent.",
        "Possible password guessing against {host} {svc} from {src_ip}.",
        "Credential-guessing pattern on {svc}: {src_ip} opened session after session to {host}.",
        "Login service at {dst_ip} saw {pkts} packets of rapid authentication traffic from {src_ip}.",
        "{host} {svc} under repeated login traffic ({proto}) from {src_ip}, lasting {dur}s.",
        "Brute-force signature on {proto}/{svc}: source {src_ip}, destination {host} ({dst_ip}), duration {dur}s.",
        "Too many authentication exchanges: {src_ip} to {host} over {svc}, {bytes_out} bytes out.",
        "Login-service flood toward {dst_ip} ({host}) from {src_ip}: {pkts} packets over {dur}s on {svc}.",
        "Watch {src_ip}: rapid-fire {svc} logins against {host}, {pkts} packets so far.",
    ],
    "R-NET-EXPLOIT": [
        "Exploit-like payload from {src_ip} to {host} ({dst_ip}) on {svc}: {bytes_out} bytes sent, {bytes_in} returned.",
        "Suspicious request pattern against {svc} on {dst_ip} from {src_ip}.",
        "{src_ip} sent {bytes_out} bytes to {host} over {proto}/{svc} matching an attack signature.",
        "Malformed or hostile input reached {host} {svc}; sender {src_ip}, {pkts} packets.",
        "Payload inspection flagged traffic to {dst_ip}: {src_ip}, {proto}, {bytes_out} bytes in {dur}s.",
        "Web or service attack indicator on {host}. Client {src_ip}, service {svc}, response {bytes_in} bytes.",
        "IDS signature hit: possible exploitation of {host} ({dst_ip}) {svc} by {src_ip}; {pkts} packets.",
        "Request from {src_ip} to {svc} on {host} looked like an injection or overflow attempt ({bytes_out} bytes).",
        "Attack traffic suspected toward {dst_ip}: source {src_ip}, service {svc}, {bytes_out} bytes in, {bytes_in} bytes back.",
        "Exploit signature matched on {proto}/{svc}. {src_ip} talking to {host} for {dur} seconds.",
    ],
    "R-NET-DOS": [
        "High packet rate toward {host} ({dst_ip}) from {src_ip}: {rate} packets/s on {svc}.",
        "{src_ip} is flooding {dst_ip} with {pkts} packets over {dur}s.",
        "Traffic volume anomaly against {host}: {rate} pkt/s from {src_ip}, {proto}/{svc}.",
        "Load spike on {host} {svc}: {src_ip} drove {rate} packets per second.",
        "Flood-like traffic: {pkts} packets from {src_ip} hit {dst_ip} within {dur} seconds.",
        "{host} is receiving abnormal volume ({rate} pkt/s) on {svc}; top talker {src_ip}.",
        "Possible DoS: target {dst_ip} ({host}), source {src_ip}, rate {rate} packets per second.",
        "Rate threshold exceeded on {svc} at {host}: {src_ip}, {pkts} packets, {bytes_out} bytes.",
        "Service {svc} on {host} under heavy load from {src_ip}; {pkts} packets, {dur}s.",
        "Availability risk for {dst_ip}: sustained {proto} traffic from {src_ip} at {rate} pkt/s.",
    ],
    "R-NET-C2": [
        "{host} ({src_ip}) sent {bytes_out} bytes to external {dst_ip} over {proto}/{svc}.",
        "Outbound session from {src_ip} to {dst_ip}: {bytes_out} bytes out, {bytes_in} bytes in, {dur}s.",
        "Unusual outbound traffic from {host} to {dst_ip} on {svc}.",
        "{host} reached out to {dst_ip} over {svc}; upload {bytes_out} bytes, download {bytes_in} bytes.",
        "Egress anomaly: internal {src_ip} kept a {proto} session with {dst_ip} open for {dur}s.",
        "Large or periodic outbound flow from {host} to external host {dst_ip} ({pkts} packets).",
        "Possible beaconing or data transfer: internal {src_ip} ({host}) -> external {dst_ip}, {pkts} packets.",
        "Outbound {svc} from {host}: destination {dst_ip}, {bytes_out} bytes leaving the network.",
        "External communication flagged: {host} talked to {dst_ip} for {dur}s, {bytes_out} bytes uploaded.",
        "Check {host}: it exchanged {pkts} packets with {dst_ip} ({proto}/{svc}), mostly outbound.",
    ],
    "R-NET-MALWARE": [
        "Malware-like traffic between {src_ip} and {host} ({dst_ip}) on {svc}: {pkts} packets.",
        "{src_ip} -> {dst_ip} matched a malware traffic pattern over {proto}.",
        "Traffic resembling a backdoor or worm toward {host} from {src_ip}, {bytes_out} bytes.",
        "Known-bad traffic shape seen at {host}: peer {src_ip}, {svc}, {dur}s.",
        "Malicious-software indicator on the wire: {src_ip} and {dst_ip}, {pkts} packets, {proto}.",
        "{host} involved in a session that looks like remote-access malware (peer {src_ip}).",
        "Malware signature: source {src_ip}, destination {dst_ip} ({host}), service {svc}, {dur}s.",
        "Session to {host} from {src_ip} fits a worm or backdoor profile; {bytes_out} bytes transferred.",
        "Suspected malicious session to {host}: {src_ip} sent {bytes_out} bytes over {proto}/{svc}.",
        "Threat pattern match: {pkts} packets between {src_ip} and {host}, {svc}, {bytes_in} bytes returned.",
    ],
    "R-EDR-PROC": [
        "{process} ran on {host} as {user} ({event}): {args}",
        "Process {process} started by {user} on {host}; event {event}, arguments: {args}",
        "Endpoint agent flagged {process} on {host} (user {user}).",
        "{user} on {host} triggered {event} through {process}. Details: {args}",
        "Unexpected {event} by {process} on {host}; account {user}.",
        "Host {host} reports {process} activity ({event}) under {user}: {args}",
        "Suspicious execution on {host}: {event} by {process}, user {user}, args {args}",
        "{process} ({event}) on {host} looked out of place for {user}.",
        "EDR alert for {host}: {user} ran {process} ({event}) with {args}",
        "Behaviour rule hit: {process} by {user} on {host}, {event}, {args}",
    ],
    "R-AUTH-FAIL": [
        "{failures} failed logins to {host} via {auth} from {src_ip}, across {n_users} account(s).",
        "Repeated authentication failures from {src_ip} against {host} ({auth}): {failures} in {minutes} min.",
        "{n_users} account(s) failed to log in to {host} {failures} times from {src_ip}.",
        "Bad password events for {user} and others: {failures} on {host} from {src_ip}.",
        "{auth} logins to {host} kept failing ({failures} times, {minutes} min) from {src_ip}.",
        "Failed sign-ins from {src_ip}: {failures} attempts against {host}, {n_users} account(s) involved.",
        "Login failure burst on {host}: source {src_ip}, service {auth}, {failures} failures, {n_users} account(s), {minutes} min.",
        "{src_ip} produced {failures} rejected {auth} logons at {host} in {minutes} minutes.",
        "Auth monitor: {failures} bad-password events for {host} from {src_ip} within {minutes} minutes.",
        "Authentication errors piling up on {host}: {failures} from {src_ip}, account {user} among them.",
    ],
    "R-AUTH-LOCK": [
        "Account {user} locked out on {host} after {failures} failures from {src_ip}.",
        "{user} was locked out ({auth}) following {failures} failed attempts from {src_ip}.",
        "Lockout of {user} on {host}; source {src_ip}.",
        "{host} disabled sign-in for {user} after {failures} wrong passwords ({minutes} min).",
        "Account {user} hit the lockout threshold via {auth}; attempts came from {src_ip}.",
        "Lockout event: {user}, {failures} failures, origin {src_ip}, service {auth}.",
        "Account lockout: user {user}, host {host}, service {auth}, {failures} failures in {minutes} min from {src_ip}.",
        "{user} can no longer log in to {host}: {failures} failed {auth} attempts from {src_ip}.",
        "Directory locked {user} after {failures} bad passwords within {minutes} minutes; origin {src_ip}.",
        "{src_ip} caused a lockout of {user} on {host} ({failures} tries).",
    ],
    "R-AUTH-REMOTE": [
        "{user} logged on to {host} via {auth} from {src_ip} after {failures} failed attempt(s).",
        "Remote logon by {user} to {host} from {src_ip} ({auth}); {n_hosts} host(s) reached in {minutes} min.",
        "Unusual {auth} logon for {user} on {host} from {src_ip}.",
        "{auth} session opened on {host} for {user}, coming from {src_ip}.",
        "{user} reached {n_hosts} host(s) including {host} within {minutes} minutes ({auth}).",
        "Successful remote sign-in: {user} at {host}, source {src_ip}, {failures} earlier failure(s).",
        "Remote access: account {user}, source {src_ip}, target {host}, method {auth}, prior failures {failures}.",
        "{host} accepted a {auth} logon from {src_ip} for {user}.",
        "Logon anomaly for {user}: {auth} session to {host} from {src_ip}, {n_hosts} host(s) within {minutes} minutes.",
        "New remote session: {user} on {host} via {auth} ({src_ip}), {failures} failed tries first.",
    ],
}


# --------------------------------------------------------------------------- builders

class Builder:
    """Produces items of one kind. Each item becomes one alert."""

    def __init__(self, name, rule, category, disposition, n):
        self.name, self.rule, self.category, self.disposition, self.n = name, rule, category, disposition, n


GROUP_OWNER: dict[str, str] = {}  # source group -> the one builder allowed to use it


def sample(pool, n, rng, used, per_group=2, builder=None):
    """Pick up to n unused rows, at most per_group from one source group.

    A source group is only ever used by one builder, so it lands in one
    (category, disposition) stratum and therefore in one split.
    """
    taken, per = [], Counter()
    for idx in rng.permutation(len(pool)):
        row = pool[idx]
        ref = (row["dataset"], row["file"], row["row"])
        owner = GROUP_OWNER.get(row["group"])
        if ref in used or per[row["group"]] >= per_group or (owner and owner != builder):
            continue
        taken.append(row)
        used.add(ref)
        per[row["group"]] += 1
        GROUP_OWNER[row["group"]] = builder
        if len(taken) == n:
            break
    return taken


def top_share(rows, key, share=0.05, at_least=50):
    """The rows with the largest `key`: the top 5%, but never fewer than `at_least`."""
    rows = [r for r in rows if r[key] > 0]
    keep = max(int(len(rows) * share), min(len(rows), at_least))
    return sorted(rows, key=lambda r: (-r[key], r["dataset"], str(r["file"]), r["row"]))[:keep]


def make_time(key, window=None, business=False) -> dt.datetime:
    """Map an item into the PoC period. Windows follow the inventory's approved activity."""
    days = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4, "Saturday": 5, "Sunday": 6}
    if window:
        candidates = [d for d in range(PERIOD_DAYS)
                      if window["day"] == "daily"
                      or (window["day"] == "weekdays" and (PERIOD_START + dt.timedelta(days=d)).weekday() < 5)
                      or (PERIOD_START + dt.timedelta(days=d)).weekday() == days.get(window["day"])]
        day = pick(candidates, key, "day")
        sh, sm = map(int, window["start"].split(":"))
        eh, em = map(int, window["end"].split(":"))
        start, end = sh * 60 + sm, eh * 60 + em
        if end <= start:
            end += 24 * 60
        minute = start + hnum(key, "min") % (end - start)
        return PERIOD_START + dt.timedelta(days=day, minutes=minute, seconds=hnum(key, "s") % 60)
    if business:
        weekdays = [d for d in range(PERIOD_DAYS) if (PERIOD_START + dt.timedelta(days=d)).weekday() < 5]
        day = pick(weekdays, key, "day")
        minute = 9 * 60 + hnum(key, "min") % (9 * 60)
        return PERIOD_START + dt.timedelta(days=day, minutes=minute, seconds=hnum(key, "s") % 60)
    return PERIOD_START + dt.timedelta(seconds=hnum(key, "t") % (PERIOD_DAYS * 86400))


class Generator:
    def __init__(self, raw_dir: Path, inventory: Inventory, seed: int):
        self.raw_dir, self.inv, self.seed = raw_dir, inventory, seed
        self.rng = np.random.RandomState(seed)
        self.inputs, self.warnings, self.items = [], [], []
        self.used = set()
        GROUP_OWNER.clear()
        self.fixture = (raw_dir / FIXTURE_MARKER).exists()

        def opt(sub, loader):
            folder = raw_dir / sub
            if folder.is_dir() and any(folder.iterdir()):
                return loader(folder, self.inputs)
            self.warnings.append(f"no {sub} files found under {raw_dir}")
            return []

        net = opt("unsw_nb15", load_unsw) + opt("cicids2017", load_cicids)
        self.beth = opt("beth", load_beth)
        self.lanl = opt("lanl", load_lanl_redteam)
        self.net_attack = defaultdict(list)
        self.net_benign = []
        for r in net:
            (self.net_attack[r["raw_label"]] if r["attack"] else self.net_benign).append(r)

    # pools of attack rows by taxonomy category
    def attack_pool(self, *labels):
        out = []
        for lab in labels:
            if lab.endswith("*"):
                out += [r for k, v in self.net_attack.items() if k.startswith(lab[:-1]) for r in v]
            else:
                out += self.net_attack.get(lab, [])
        return out

    def add(self, b: Builder, rows, make):
        if len(rows) < b.n:
            self.warnings.append(f"{b.name}: wanted {b.n}, only {len(rows)} source rows available")
        for k, row in enumerate(rows):
            item = {"builder": b.name, "rule": b.rule, "category": b.category, "disposition": b.disposition,
                    "row": row, "key": (b.name, row.get("dataset"), row.get("file"), row.get("row"), k)}
            item.update(make(item, row))
            self.items.append(item)

    def synthetic_rows(self, b: Builder, n=None):
        n = b.n if n is None else n
        return [{"dataset": "synthetic", "file": None, "row": i, "raw_label": b.name,
                 "attack": b.disposition == "TP", "group": f"syn|{b.name}|{i}"} for i in range(n)]

    # ---- shared entity choices
    def inbound(self, item, victims):
        host = pick(victims, *item["key"], "victim")
        if frac(*item["key"], "internal") < INTERNAL_SOURCE_SHARE:
            src_host = pick([h for h in self.inv.workstations() + self.inv.by_role("lab_machine", "test_vm")
                             if h != host], *item["key"], "srchost")
            src = self.inv.ip(src_host)
        else:
            src = external_ip(*item["key"])
        return {"host": host, "src_ip": src, "dst_ip": self.inv.ip(host)}

    def net_fields(self, row):
        return {"proto": row["proto"], "service": row["service"], "dst_port": row["dst_port"],
                "observables": {"packets": row["pkts"], "bytes_out": row["bytes_out"],
                                "bytes_in": row["bytes_in"], "duration_s": round(row["dur"], 3),
                                "packet_rate": round(row["pkt_rate"], 1)}}

    # ---- builders
    def build(self):
        inv = self.inv
        servers = inv.by_role("web_server", "application_server", "mail_server")
        all_hosts = [h for h in inv.hosts if h != "scanner-01"]
        brute_targets = servers + ["dc-01", "db-prod-01", "dev-lab-01", "dev-lab-02", "ws-eng-201", "ws-eng-202"]
        exploit_targets = servers + ["db-prod-01", "dev-lab-01", "test-vm-01"]
        dos_targets = inv.by_role("web_server", "mail_server") + ["app-prod-01", "dc-01", "dev-lab-02"]
        endpoint_hosts = inv.workstations() + ["dev-lab-01", "test-vm-01", "app-prod-01", "web-prod-02"]

        def net_inbound(victims, stage_fn=lambda row: 1, spread_fn=lambda row: False):
            def make(item, row):
                ent = self.inbound(item, victims)
                return {**ent, **self.net_fields(row), "stage": stage_fn(row), "spread": spread_fn(row),
                        "time": make_time(item["key"]), "sources": ["network"]}
            return make

        recon = self.attack_pool("Reconnaissance", "Analysis", "PortScan")
        exploit = self.attack_pool("Exploits", "Shellcode", "Fuzzers", "Generic", "Web Attack*",
                                   "Heartbleed", "Infiltration")
        dos = self.attack_pool("DoS", "DoS*", "DDoS")
        dos = list({id(r): r for r in dos}.values())
        benign = self.net_benign

        def exploit_stage(row):
            return {"Heartbleed": 2, "Infiltration": 3}.get(row["raw_label"], 1)

        # -- TP, network
        b = Builder("tp_scan", "R-NET-SCAN", "C1", "TP", 85)
        self.add(b, sample(recon, b.n, self.rng, self.used, builder=b.name), net_inbound(all_hosts))
        b = Builder("tp_netbrute", "R-NET-BRUTE", "C2", "TP", 45)
        self.add(b, sample(self.attack_pool("FTP-Patator", "SSH-Patator"), b.n, self.rng, self.used, builder=b.name),
                 net_inbound(brute_targets))
        b = Builder("tp_exploit", "R-NET-EXPLOIT", "C4", "TP", 85)
        self.add(b, sample(exploit, b.n, self.rng, self.used, builder=b.name), net_inbound(exploit_targets, exploit_stage))
        b = Builder("tp_dos", "R-NET-DOS", "C7", "TP", 85)
        self.add(b, sample(dos, b.n, self.rng, self.used, builder=b.name), net_inbound(dos_targets, lambda r: 2))
        b = Builder("tp_netmal", "R-NET-MALWARE", "C5", "TP", 30)
        self.add(b, sample(self.attack_pool("Backdoor", "Worms"), b.n, self.rng, self.used, builder=b.name),
                 net_inbound(endpoint_hosts, lambda r: 3, lambda r: r["raw_label"] == "Worms"))

        def outbound(stage, spread=False, dst_fn=None, src_hosts=None, window=None):
            def make(item, row):
                host = pick(src_hosts or endpoint_hosts, *item["key"], "victim")
                dst = dst_fn(item) if dst_fn else external_ip(*item["key"])
                return {"host": host, "src_ip": self.inv.ip(host), "dst_ip": dst, **self.net_fields(row),
                        "stage": stage, "spread": spread, "time": make_time(item["key"], window),
                        "sources": ["network"]}
            return make

        b = Builder("tp_c2", "R-NET-C2", "C6", "TP", 85)
        self.add(b, sample(self.attack_pool("Bot"), b.n, self.rng, self.used, builder=b.name), outbound(4))

        # -- TP, endpoint (BETH evil rows)
        def edr(stage, hosts, user_fn, window=None):
            def make(item, row):
                host = pick(hosts, *item["key"], "host")
                return {"host": host, "user": user_fn(item, host), "process": row["process"],
                        "command_line": row["args"], "event": row["event"], "stage": stage, "spread": False,
                        "time": make_time(item["key"], window), "sources": ["endpoint"],
                        "observables": {"event": row["event"]}}
            return make

        def host_user(item, host):
            return self.inv.owner(host) or pick(["lab.tester", "svc_deploy", "j.thomas"], *item["key"], "u")

        b = Builder("tp_edr", "R-EDR-PROC", "C5", "TP", 55)
        self.add(b, sample([r for r in self.beth if r["evil"] == 1], b.n, self.rng, self.used, builder=b.name),
                 edr(3, endpoint_hosts, host_user))

        # -- TP, authentication (LANL red team if present, otherwise labelled synthetic)
        users = [u for u, a in inv.accounts.items() if a["type"] in ("user", "service", "admin")]

        def auth(stage, rule_kind, window=None, business=False, spread=False):
            def make(item, row):
                k = item["key"]
                if rule_kind == "spray":
                    host = pick(["dc-01", "mail-01", "web-prod-01", "app-prod-01"], *k, "host")
                    n_users = 3 + hnum(*k, "nu") % 6
                    targeted = [pick(users, *k, "user", i) for i in range(n_users)]
                    targeted = list(dict.fromkeys(targeted))
                    src = self.inbound(item, [host])["src_ip"]
                    return {"host": host, "users": targeted, "user": targeted[0], "src_ip": src,
                            "auth": pick(["kerberos", "ssh", "rdp", "imap"], *k, "a"),
                            "failures": 15 + hnum(*k, "f") % 45, "minutes": 3 + hnum(*k, "m") % 25,
                            "n_hosts": 1, "success_after": False, "lockout": False}
                if rule_kind == "lockout_attack":
                    host = pick(["dc-01", "mail-01"], *k, "host")
                    user = pick(users, *k, "user")
                    return {"host": host, "users": [user], "user": user,
                            "src_ip": self.inbound(item, [host])["src_ip"], "auth": "kerberos",
                            "failures": 10 + hnum(*k, "f") % 30, "minutes": 2 + hnum(*k, "m") % 10,
                            "n_hosts": 1, "success_after": False, "lockout": True}
                if rule_kind in ("compromise", "lateral"):
                    host = pick(servers + ["dc-01", "db-prod-01"] + inv.workstations(), *k, "host")
                    user = pick(users, *k, "user")
                    if rule_kind == "lateral":  # lateral movement starts from an already-compromised inside host
                        src = inv.ip(pick([w for w in inv.workstations() if w != host], *k, "src"))
                    else:
                        src = self.inbound(item, [host])["src_ip"]
                    n_hosts = 1 if rule_kind == "compromise" else 3 + hnum(*k, "nh") % 4
                    return {"host": host, "users": [user], "user": user, "src_ip": src,
                            "auth": pick(["rdp", "ssh", "smb", "kerberos"], *k, "a"),
                            "failures": hnum(*k, "f") % 12, "minutes": 5 + hnum(*k, "m") % 55,
                            "n_hosts": n_hosts, "success_after": True, "lockout": False}
                if rule_kind == "typo":
                    host = pick(inv.workstations(), *k, "host")
                    user = inv.owner(host)
                    return {"host": "dc-01", "users": [user], "user": user, "src_ip": inv.ip(host),
                            "auth": "kerberos", "failures": 2 + hnum(*k, "f") % 3,
                            "minutes": 1 + hnum(*k, "m") % 3, "n_hosts": 1, "success_after": True,
                            "lockout": False, "user_workstation": host}
                if rule_kind == "forgot":
                    host = pick(inv.workstations(), *k, "host")
                    user = inv.owner(host)
                    return {"host": "dc-01", "users": [user], "user": user, "src_ip": inv.ip(host),
                            "auth": "kerberos", "failures": 5 + hnum(*k, "f") % 2,
                            "minutes": 2 + hnum(*k, "m") % 8, "n_hosts": 1, "success_after": False,
                            "lockout": True, "user_workstation": host}
                if rule_kind == "admin":
                    appr = inv.approved["admin-maintenance"]
                    host = pick(appr["targets"], *k, "host")
                    user = pick(appr["actor_accounts"], *k, "user")
                    src_host = pick(["ws-eng-201", "ws-eng-202"], *k, "src")
                    return {"host": host, "users": [user], "user": user, "src_ip": inv.ip(src_host),
                            "auth": "rdp", "failures": hnum(*k, "f") % 2, "minutes": 5 + hnum(*k, "m") % 40,
                            "n_hosts": 1, "success_after": True, "lockout": False}
                if rule_kind == "helpdesk":
                    appr = inv.approved["helpdesk-support"]
                    host = pick(appr["targets"], *k, "host")
                    return {"host": host, "users": ["it.support"], "user": "it.support",
                            "src_ip": inv.ip(appr["actor_host"]), "auth": "rdp", "failures": hnum(*k, "f") % 2,
                            "minutes": 5 + hnum(*k, "m") % 30, "n_hosts": 1, "success_after": True,
                            "lockout": False}
                if rule_kind == "remote_typo":  # an employee mistyping their password on the VPN from home
                    user = pick([u for u, a in inv.accounts.items() if a["type"] == "user"], *k, "user")
                    return {"host": "vpn-01", "users": [user], "user": user, "src_ip": external_ip(*k, "home"),
                            "auth": "vpn", "failures": 2 + hnum(*k, "f") % 3, "minutes": 1 + hnum(*k, "m") % 4,
                            "n_hosts": 1, "success_after": True, "lockout": False}
                raise ValueError(rule_kind)

            def wrapped(item, row):
                fields = make(item, row)
                fields.update({"stage": stage, "spread": spread or fields.get("n_hosts", 1) > 1,
                               "time": make_time(item["key"], window, business), "sources": ["auth"]})
                return fields
            return wrapped

        b = Builder("tp_authfail", "R-AUTH-FAIL", "C2", "TP", 25)
        self.add(b, self.synthetic_rows(b), auth(1, "spray"))
        b = Builder("tp_authlock", "R-AUTH-LOCK", "C2", "TP", 15)
        self.add(b, self.synthetic_rows(b), auth(1, "lockout_attack"))
        b = Builder("tp_remote", "R-AUTH-REMOTE", "C3", "TP", 55)
        rows = sample(self.lanl, b.n, self.rng, self.used, per_group=1, builder=b.name) if self.lanl else self.synthetic_rows(b)
        if not self.lanl:
            self.warnings.append("no LANL red-team file: C3 alerts are labelled synthetic")
        self.add(b, rows, auth(3, "compromise"))
        b = Builder("tp_lateral", "R-AUTH-REMOTE", "C3", "TP", 30)
        self.add(b, self.synthetic_rows(b), auth(4, "lateral"))

        # -- BTP: authorised activity (B1). Real attack-behaviour rows re-attributed via the overlay.
        scan = inv.approved["vuln-scan"]
        b = Builder("b1_scan", "R-NET-SCAN", "B1", "BTP", 30)
        scan_targets = [h for h, v in inv.hosts.items() if h != "scanner-01" and
                        any(ipaddress.ip_address(v["ip"]) in ipaddress.ip_network(n) for n in scan["targets"])]

        def approved_scan(item, row):
            host = pick(scan_targets, *item["key"], "victim")
            return {"host": host, "src_ip": inv.ip(scan["actor_host"]), "dst_ip": inv.ip(host),
                    **self.net_fields(row), "stage": 0, "spread": False,
                    "time": make_time(item["key"], scan["window"]), "sources": ["network"]}
        self.add(b, sample(recon, b.n, self.rng, self.used, builder=b.name), approved_scan)

        load = inv.approved["load-test"]
        b = Builder("b1_loadtest", "R-NET-DOS", "B1", "BTP", 15)

        def load_test(item, row):
            host = pick(load["targets"], *item["key"], "victim")
            return {"host": host, "src_ip": inv.ip(load["actor_host"]), "dst_ip": inv.ip(host),
                    **self.net_fields(row), "stage": 0, "spread": False,
                    "time": make_time(item["key"], load["window"]), "sources": ["network"]}
        self.add(b, sample(dos, b.n, self.rng, self.used, builder=b.name), load_test)

        backup = inv.approved["offsite-backup"]
        big_benign = top_share(benign, "bytes_out")
        b = Builder("b1_backup", "R-NET-C2", "B1", "BTP", 15)
        self.add(b, sample(big_benign, b.n, self.rng, self.used, builder=b.name),
                 outbound(0, dst_fn=lambda it: backup["destination_ip"], src_hosts=[backup["actor_host"]],
                          window=backup["window"]))

        b = Builder("b1_helpdesk", "R-AUTH-REMOTE", "B1", "BTP", 15)
        self.add(b, self.synthetic_rows(b), auth(0, "helpdesk", window=inv.approved["helpdesk-support"]["window"]))

        pentest = inv.approved["external-pentest"]
        b = Builder("b1_pentest", "R-NET-EXPLOIT", "B1", "BTP", 10)

        def approved_pentest(item, row):
            host = pick(pentest["targets"], *item["key"], "victim")
            return {"host": host, "src_ip": pentest["actor_ip"], "dst_ip": inv.ip(host), **self.net_fields(row),
                    "stage": 0, "spread": False, "time": make_time(item["key"], pentest["window"]),
                    "sources": ["network"]}
        self.add(b, sample(exploit, b.n, self.rng, self.used, builder=b.name), approved_pentest)

        b = Builder("b1_admin", "R-AUTH-REMOTE", "B1", "BTP", 15)
        self.add(b, self.synthetic_rows(b), auth(0, "admin", window=inv.approved["admin-maintenance"]["window"]))

        patch = inv.approved["patch-deploy"]
        b = Builder("b1_patch", "R-EDR-PROC", "B1", "BTP", 10)
        self.add(b, sample([r for r in self.beth if r["sus"] == 0 and r["evil"] == 0], b.n, self.rng, self.used, builder=b.name),
                 edr(0, patch["targets"], lambda it, h: "svc_deploy", window=patch["window"]))

        # -- BTP: user error (B2)
        b = Builder("b2_typo", "R-AUTH-FAIL", "B2", "BTP", 40)
        self.add(b, self.synthetic_rows(b), auth(0, "typo", business=True))
        b = Builder("b2_lockout", "R-AUTH-LOCK", "B2", "BTP", 30)
        self.add(b, self.synthetic_rows(b), auth(0, "forgot", business=True))
        web_benign = [r for r in benign if r["service"] in ("http", "https") or r["dst_port"] in (80, 443)]
        b = Builder("b2_remote_typo", "R-AUTH-FAIL", "B2", "BTP", 15)
        self.add(b, self.synthetic_rows(b), auth(0, "remote_typo"))
        b = Builder("b2_url", "R-NET-EXPLOIT", "B2", "BTP", 25)

        def mistyped_url(item, row):
            src_host = pick(inv.workstations(), *item["key"], "src")
            host = pick(inv.by_role("web_server", "application_server"), *item["key"], "victim")
            return {"host": host, "src_ip": inv.ip(src_host), "dst_ip": inv.ip(host), **self.net_fields(row),
                    "stage": 0, "spread": False, "time": make_time(item["key"], business=True),
                    "sources": ["network"]}
        self.add(b, sample(web_benign, b.n, self.rng, self.used, builder=b.name), mistyped_url)

        # -- FP: loose rules over rows the dataset labels benign.
        # Each FP pool is narrowed to rows that look like its TP counterpart's rows:
        # same dataset, same service (including "none") and the same presence of a
        # port. Otherwise which fields are filled in could tell TP from FP.
        def shape(r):
            return (r["dataset"], r["service"], r["dst_port"] is None)

        def like_tp(tp_builder, rows, minimum=20):
            shapes = {shape(it["row"]) for it in self.items if it["builder"] == tp_builder}
            matched = [r for r in rows if shape(r) in shapes]
            if len(matched) >= minimum:
                return matched
            self.warnings.append(f"FP pool for {tp_builder}: only {len(matched)} benign rows match its TP rows; "
                                 "using the unmatched pool")
            return rows

        brute_benign = [r for r in benign if r["service"] in ("ssh", "ftp") or r["dst_port"] in (21, 22)]
        fp = [("fp_scan", "R-NET-SCAN", "C1", 30, top_share(like_tp("tp_scan", benign), "pkts"), all_hosts),
              ("fp_netbrute", "R-NET-BRUTE", "C2", 25, like_tp("tp_netbrute", brute_benign), brute_targets),
              ("fp_exploit", "R-NET-EXPLOIT", "C4", 30, like_tp("tp_exploit", benign), exploit_targets),
              ("fp_dos", "R-NET-DOS", "C7", 25, top_share(like_tp("tp_dos", benign), "pkt_rate"), dos_targets),
              ("fp_netmal", "R-NET-MALWARE", "C5", 15, top_share(like_tp("tp_netmal", benign), "dur"),
               endpoint_hosts)]
        for name, rule, cat, n, pool, victims in fp:
            b = Builder(name, rule, cat, "FP", n)
            self.add(b, sample(pool, n, self.rng, self.used, builder=b.name), net_inbound(victims, lambda r: 0))
        b = Builder("fp_c2", "R-NET-C2", "C6", "FP", 30)
        self.add(b, sample(big_benign, b.n, self.rng, self.used, builder=b.name), outbound(0))
        b = Builder("fp_edr", "R-EDR-PROC", "C5", "FP", 25)
        self.add(b, sample([r for r in self.beth if r["sus"] == 1 and r["evil"] == 0], b.n, self.rng, self.used, builder=b.name),
                 edr(0, endpoint_hosts, host_user))
        return self

    # ------------------------------------------------------------------- splitting

    def split(self):
        strata = defaultdict(lambda: defaultdict(list))
        for it in self.items:
            strata[(it["category"], it["disposition"])][it["row"]["group"]].append(it)
        for (cat, disp), groups in strata.items():
            order = sorted(groups, key=lambda g: hnum(self.seed, "split", g))
            total = sum(len(groups[g]) for g in order)
            targets, acc = [], 0.0
            for name, ratio in SPLIT_RATIOS:
                acc += ratio
                targets.append((name, round(acc * total)))
            if total >= 3:  # val and test each get at least one alert
                n_val = max(1, round(0.2 * total))
                n_test = max(1, round(0.2 * total))
                targets = [("train", total - n_val - n_test), ("val", total - n_test), ("test", total)]
            done = 0
            for g in order:
                split = next(name for name, upto in targets if done < upto)
                for it in groups[g]:
                    it["split"] = split
                done += len(groups[g])
        return self

    # ------------------------------------------------------------------- output

    def render(self, it):
        inv = self.inv
        k = it["key"]
        alert_id = "ALR-" + hashlib.sha256(f"{self.seed}|{k}".encode()).hexdigest()[:12].upper()
        variant = pick(SPLIT_VARIANTS[it["split"]], *k, "variant")
        rule_name, source_system = RULES[it["rule"]]
        svc = it.get("service") or (f"port {it['dst_port']}" if it.get("dst_port") else "an unknown service")
        obs = it.get("observables", {})
        values = {
            "src_ip": it.get("src_ip"), "dst_ip": it.get("dst_ip"), "host": it.get("host"),
            "svc": svc, "proto": it.get("proto", "tcp"), "pkts": obs.get("packets"),
            "bytes_out": obs.get("bytes_out"), "bytes_in": obs.get("bytes_in"),
            "dur": obs.get("duration_s"), "rate": obs.get("packet_rate"),
            "process": it.get("process"), "args": (it.get("command_line") or "")[:120] or "(none)",
            "event": it.get("event"), "user": it.get("user") or ", ".join(it.get("users", []) or []),
            "auth": it.get("auth"), "failures": it.get("failures"), "minutes": it.get("minutes"),
            "n_users": len(it.get("users") or []), "n_hosts": it.get("n_hosts"),
        }
        description = TEMPLATES[it["rule"]][variant].format(**values)

        alert = {
            "alert_id": alert_id,
            "timestamp": it["time"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rule_id": it["rule"], "rule_name": rule_name, "source_system": source_system,
            "description": description,
            "src_ip": it.get("src_ip"), "dst_ip": it.get("dst_ip"), "dst_port": it.get("dst_port"),
            "protocol": it.get("proto"), "service": it.get("service"),
            "host": it.get("host"), "user": it.get("user"), "users": it.get("users"),
            "process": it.get("process"), "command_line": it.get("command_line"), "file_hash": None,
            "observables": obs or {k2: it.get(k2) for k2 in
                                   ("auth", "failures", "minutes", "n_hosts", "success_after", "lockout")},
        }
        alert = {k2: v for k2, v in alert.items() if v not in (None, [], {})}

        users = it.get("users") or ([it["user"]] if it.get("user") else [])
        tier = inv.tier(it.get("host"), users)
        stage = it["stage"]
        spread = bool(it.get("spread")) and stage >= 2
        level = severity(stage, tier, spread=spread)
        gt = {
            "alert_id": alert_id, "split": it["split"], "category": it["category"],
            "disposition": it["disposition"], "stage": stage, "asset_tier": tier,
            "modifiers": {"spread": spread, "ongoing": False}, "final_severity": level,
            "investigation_depth": investigation_depth(level),
            "expected_iocs": self.expected_iocs(it, users),
            "expected_log_sources": it["sources"],
            "acceptable_actions": self.acceptable_actions(it, tier),
            "provenance": {
                "builder": it["builder"], "dataset": it["row"]["dataset"], "file": it["row"].get("file"),
                "row": it["row"].get("row"), "raw_label": it["row"].get("raw_label"),
                "group": it["row"]["group"], "is_synthetic": it["row"]["dataset"] == "synthetic",
                "is_overlay": it["row"]["dataset"] != "synthetic",
            },
        }
        overlay = None
        if it["row"]["dataset"] != "synthetic":
            row = it["row"]
            overlay = {"alert_id": alert_id, "dataset": row["dataset"], "file": row.get("file"),
                       "row": row.get("row"),
                       "original": {k2: row.get(k2) for k2 in ("orig_src", "orig_dst", "orig_host", "orig_user",
                                                               "orig_ts", "uid") if row.get(k2) is not None},
                       "mapped": {"src_ip": it.get("src_ip"), "dst_ip": it.get("dst_ip"), "host": it.get("host"),
                                  "user": it.get("user"), "timestamp": alert["timestamp"]}}
        return alert, gt, overlay

    def expected_iocs(self, it, users):
        ips = [ip for ip in (it.get("src_ip"), it.get("dst_ip")) if ip]
        return {"ips": ips, "hosts": [it["host"]] if it.get("host") else [], "users": users,
                "processes": [it["process"]] if it.get("process") else []}

    def acceptable_actions(self, it, tier):
        if it["disposition"] != "TP":
            return ["close_benign"]
        acts = ["escalate_tier2"]
        src = it.get("src_ip") or ""
        external = src and not any(ipaddress.ip_address(src) in n for n in self.inv.networks)
        if it["category"] == "C6":
            external = bool(it.get("dst_ip"))
        if external:
            acts.append("block_ip")
        if it["category"] in ("C2", "C3") and (it.get("user") or it.get("users")):
            acts.append("reset_credentials")
        if it["category"] == "C3":
            acts.append("disable_user")
        if it["stage"] >= 3 and it["category"] in ("C3", "C4", "C5", "C6") and \
                it.get("host") not in self.inv.critical_list:
            acts.append("isolate_host")
        return acts

    def write(self, out: Path):
        out.mkdir(parents=True, exist_ok=True)
        files = {s: (open(out / f"alerts_{s}.jsonl", "w"), open(out / f"ground_truth_{s}.jsonl", "w"))
                 for s, _ in SPLIT_RATIOS}
        overlay_f = open(out / "overlay.jsonl", "w")
        counts = Counter()
        for it in sorted(self.items, key=lambda x: (x["split"], x["time"])):
            alert, gt, overlay = self.render(it)
            af, gf = files[it["split"]]
            af.write(json.dumps(alert, sort_keys=True) + "\n")
            gf.write(json.dumps(gt, sort_keys=True) + "\n")
            if overlay:
                overlay_f.write(json.dumps(overlay, sort_keys=True, default=str) + "\n")
            counts[(it["split"], it["category"], it["disposition"])] += 1
        for af, gf in files.values():
            af.close()
            gf.close()
        overlay_f.close()
        manifest = {
            "generator_version": GENERATOR_VERSION, "seed": self.seed,
            "fixture": self.fixture,
            "fixture_note": "Built from made-up test rows, NOT the real datasets. Do not use for evaluation."
            if self.fixture else None,
            "inputs": self.inputs, "warnings": self.warnings,
            "total_alerts": len(self.items),
            "counts": [{"split": s, "category": c, "disposition": d, "n": n}
                       for (s, c, d), n in sorted(counts.items())],
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest


def main(argv=None):
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=root / "data" / "raw")
    ap.add_argument("--inventory", type=Path, default=root / "data" / "poc" / "asset_inventory.yaml")
    ap.add_argument("--out", type=Path, default=root / "data" / "poc_alerts")
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args(argv)

    gen = Generator(args.raw_dir, Inventory(args.inventory), args.seed)
    if gen.fixture and args.out.resolve() == (root / "data" / "poc_alerts").resolve():
        raise SystemExit("raw dir is test fixture data; write it somewhere other than data/poc_alerts")
    manifest = gen.build().split().write(args.out)
    print(f"wrote {manifest['total_alerts']} alerts to {args.out}")
    for w in manifest["warnings"]:
        print("warning:", w)


if __name__ == "__main__":
    main()
