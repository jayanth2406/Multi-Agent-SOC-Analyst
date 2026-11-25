"""Tests for the PoC alert generator, its checker and the severity rubric.

Uses made-up fixture rows in the real dataset formats, so no real data is needed.
"""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import build_poc_alerts  # noqa: E402
import check_poc_alerts  # noqa: E402
import make_raw_fixture  # noqa: E402
from poc_rubric import severity  # noqa: E402


@pytest.fixture(scope="module")
def raw(tmp_path_factory):
    folder = tmp_path_factory.mktemp("raw")
    make_raw_fixture.main(folder)
    return folder


def build(raw, out):
    build_poc_alerts.main(["--raw-dir", str(raw), "--out", str(out)])
    return out


def digest(folder):
    h = hashlib.sha256()
    for p in sorted(folder.glob("*")):
        h.update(p.read_bytes())
    return h.hexdigest()


def test_built_set_passes_every_check(raw, tmp_path):
    out = build(raw, tmp_path / "set")
    assert check_poc_alerts.check(out)


def test_build_is_deterministic(raw, tmp_path):
    assert digest(build(raw, tmp_path / "a")) == digest(build(raw, tmp_path / "b"))


def test_fixture_data_cannot_overwrite_the_real_set(raw):
    with pytest.raises(SystemExit):
        build_poc_alerts.main(["--raw-dir", str(raw), "--out", str(ROOT / "data" / "poc_alerts")])


@pytest.mark.parametrize("stage,tier,mods,expected", [
    (0, "Low", {}, "Informational"),                     # worked example 1
    (1, "Standard", {}, "Low"),                          # worked example 2
    (2, "High", {"ongoing": True}, "High"),              # worked example 3
    (3, "Critical", {}, "Critical"),                     # worked example 4
    (4, "Standard", {"spread": True}, "Critical"),       # worked example 5
    (1, "Critical", {"spread": True, "ongoing": True}, "High"),  # modifiers cap at one level
])
def test_rubric_matches_the_worked_examples(stage, tier, mods, expected):
    assert severity(stage, tier, **mods) == expected


def test_triage_experiment_runs_and_is_deterministic(raw, tmp_path):
    import json

    import triage_experiment

    data = build(raw, tmp_path / "set")
    outs = []
    for run in ("a", "b"):
        triage_experiment.main(["--data", str(data), "--out", str(tmp_path / run),
                                "--model-out", str(tmp_path / run / "m.joblib"), "--bootstrap", "20"])
        outs.append(json.loads((tmp_path / run / "triage_poc_val.json").read_text()))
    assert outs[0] == outs[1]
    assert set(outs[0]["approaches"]) == {"rules", "structured", "tfidf", "hybrid"}
    for a in outs[0]["approaches"].values():
        assert 0.0 <= a["metrics"]["threat_recall"] <= 1.0


def test_approved_activity_matcher_finds_every_b1(raw, tmp_path):
    import json

    from build_poc_alerts import Inventory
    from triage_features import Context

    data = build(raw, tmp_path / "set")
    ctx = Context(Inventory(ROOT / "data" / "poc" / "asset_inventory.yaml"))
    for split in ("train", "val", "test"):
        truth = {json.loads(x)["alert_id"]: json.loads(x)
                 for x in (data / f"ground_truth_{split}.jsonl").read_text().splitlines()}
        for line in (data / f"alerts_{split}.jsonl").read_text().splitlines():
            alert = json.loads(line)
            if truth[alert["alert_id"]]["category"] == "B1":
                assert ctx.approved_match(alert), alert["alert_id"]
