"""Check a built PoC alert set against requirements DR-5 to DR-8 and the rubric.

    python scripts/check_poc_alerts.py data/poc_alerts

Exits non-zero if any check fails. Prints a short report either way.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_rubric import investigation_depth, severity  # noqa: E402

SPLITS = ("train", "val", "test")
CATEGORIES = ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "B1", "B2")
MIN_PER_CATEGORY = 15
FORBIDDEN_KEYS = re.compile(r"(label|attack_cat|ground_truth|approved|dataset|synthetic|overlay|^sus$|^evil$|"
                            r"disposition|category|severity|stage|provenance|group)", re.I)
MASKS = [(re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
         (re.compile(r"\b[a-z]+(?:-[a-z0-9]+)+\b"), "<host>"),
         (re.compile(r"\b[a-z]+[._][a-z]+\b"), "<user>"),
         (re.compile(r"\d+(?:\.\d+)?"), "<n>")]


def load(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def keys_deep(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield prefix + k
            yield from keys_deep(v, prefix + k + ".")


def mask(text: str) -> str:
    """The description with IPs, hosts, users and numbers removed: its wording skeleton."""
    for rx, rep in MASKS:
        text = rx.sub(rep, text)
    return text


def check(folder: Path) -> bool:
    failures, notes = [], []
    alerts, truth = {}, {}
    for s in SPLITS:
        for a in load(folder / f"alerts_{s}.jsonl"):
            alerts[a["alert_id"]] = (s, a)
        for g in load(folder / f"ground_truth_{s}.jsonl"):
            truth[g["alert_id"]] = g
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest.get("fixture"):
        notes.append("THIS SET IS BUILT FROM MADE-UP FIXTURE ROWS, NOT THE REAL DATASETS")

    # every alert has exactly one answer, in the same split
    if set(alerts) != set(truth):
        failures.append(f"alert/ground-truth id mismatch: {len(set(alerts) ^ set(truth))} ids")
    for aid, (s, _) in alerts.items():
        if aid in truth and truth[aid]["split"] != s:
            failures.append(f"{aid}: in alerts_{s} but ground truth says {truth[aid]['split']}")

    # DR-7: no label hints in what the agents see
    for aid, (_, a) in alerts.items():
        bad = [k for k in keys_deep(a) if FORBIDDEN_KEYS.search(k.split(".")[-1])]
        if bad:
            failures.append(f"{aid}: alert carries label-like fields {bad}")
            break

    # DR-8: size and coverage
    by_cat = Counter(g["category"] for g in truth.values())
    for c in CATEGORIES:
        if by_cat[c] < MIN_PER_CATEGORY:
            failures.append(f"category {c} has {by_cat[c]} alerts, needs at least {MIN_PER_CATEGORY}")
    for s in SPLITS:
        present = {g["category"] for g in truth.values() if g["split"] == s}
        missing = set(CATEGORIES) - present
        if missing:
            failures.append(f"split {s} has no alerts for {sorted(missing)}")

    # DR-6: no shared descriptions, wording or source groups across splits
    desc = defaultdict(set)
    skel = defaultdict(set)
    groups = defaultdict(set)
    for aid, (s, a) in alerts.items():
        desc[a["description"]].add(s)
        skel[mask(a["description"])].add(s)
        groups[truth[aid]["provenance"]["group"]].add(s)
    shared = [d for d, ss in desc.items() if len(ss) > 1]
    if shared:
        failures.append(f"{len(shared)} descriptions appear in more than one split, e.g. {shared[0]!r}")
    shared_skel = [d for d, ss in skel.items() if len(ss) > 1]
    if shared_skel:
        failures.append(f"{len(shared_skel)} wording templates appear in more than one split, e.g. {shared_skel[0]!r}")
    leaky_groups = [g for g, ss in groups.items() if len(ss) > 1]
    if leaky_groups:
        failures.append(f"{len(leaky_groups)} source groups span splits, e.g. {leaky_groups[0]}")

    # a rule name must not give away the disposition
    rule_disp = defaultdict(Counter)
    for aid, (_, a) in alerts.items():
        rule_disp[a["rule_id"]][truth[aid]["disposition"]] += 1
    for rule, c in sorted(rule_disp.items()):
        if c["TP"] == 0 or c["TP"] == sum(c.values()):
            failures.append(f"rule {rule} only ever produces {dict(c)}: its name gives away the label")

    # a field's presence must not give away the disposition within a rule
    presence = defaultdict(lambda: defaultdict(Counter))
    totals = defaultdict(Counter)
    for aid, (_, a) in alerts.items():
        tp = truth[aid]["disposition"] == "TP"
        totals[a["rule_id"]][tp] += 1
        for k in set(keys_deep(a)) - {"alert_id"}:
            presence[a["rule_id"]][k][tp] += 1
    for rule, fields in presence.items():
        for k, c in fields.items():
            if totals[rule][True] and totals[rule][False]:
                share_tp = c[True] / totals[rule][True]
                share_other = c[False] / totals[rule][False]
                if {share_tp, share_other} == {0.0, 1.0}:
                    failures.append(f"rule {rule}: field {k!r} is present only for "
                                    f"{'TP' if share_tp else 'non-TP'} alerts")

    # a field's value must not give away the disposition within a rule either
    values = defaultdict(lambda: defaultdict(lambda: {True: set(), False: set()}))
    for aid, (_, a) in alerts.items():
        tp = truth[aid]["disposition"] == "TP"
        for k in ("service", "protocol", "source_system"):
            values[a["rule_id"]][k][tp].add(a.get(k))
    for rule, fields in values.items():
        for k, v in fields.items():
            if v[True] and v[False] and not (v[True] & v[False]):
                failures.append(f"rule {rule}: {k} values for TP {sorted(map(str, v[True]))} never overlap "
                                f"with non-TP {sorted(map(str, v[False]))}")

    # DR-5 and the rubric: every answer is complete and its severity recomputes
    needed = {"category", "disposition", "stage", "asset_tier", "final_severity", "expected_iocs",
              "expected_log_sources", "acceptable_actions"}
    for aid, g in truth.items():
        miss = needed - set(g)
        if miss:
            failures.append(f"{aid}: ground truth missing {sorted(miss)}")
            continue
        expect = severity(g["stage"], g["asset_tier"], **g["modifiers"])
        if expect != g["final_severity"]:
            failures.append(f"{aid}: severity {g['final_severity']} but the rubric gives {expect}")
        if investigation_depth(expect) != g["investigation_depth"]:
            failures.append(f"{aid}: investigation depth does not match its severity")
        if g["disposition"] != "TP" and (g["stage"] != 0 or g["acceptable_actions"] != ["close_benign"]):
            failures.append(f"{aid}: a non-threat must be stage 0 with close_benign only")

    # report
    print(f"{len(alerts)} alerts in {folder}")
    for n in notes:
        print("NOTE:", n)
    by_split = Counter(g["split"] for g in truth.values())
    print("per split:", dict(by_split))
    print("per category:", dict(sorted(by_cat.items())))
    print("per disposition:", dict(Counter(g["disposition"] for g in truth.values())))
    print("per severity:", dict(Counter(g["final_severity"] for g in truth.values())))
    print("synthetic share:", round(sum(g["provenance"]["is_synthetic"] for g in truth.values()) / len(truth), 3))
    if failures:
        print(f"\nFAILED {len(failures)} check(s):")
        for f in failures:
            print(" -", f)
        return False
    print("\nall checks passed")
    return True


if __name__ == "__main__":
    sys.exit(0 if check(Path(sys.argv[1] if len(sys.argv) > 1 else "data/poc_alerts")) else 1)
