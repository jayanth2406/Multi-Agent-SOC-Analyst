"""Tests for the v1 Triage agent and its /api/v1/triage endpoints."""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import build_poc_alerts  # noqa: E402
import make_raw_fixture  # noqa: E402
import triage_experiment  # noqa: E402
from backend.agents.triage_agent import TriageAgent  # noqa: E402
from backend.main import app  # noqa: E402
from backend.models.schemas import SocAlert  # noqa: E402
from backend.triage.features import Context  # noqa: E402
from backend.triage.inventory import Inventory  # noqa: E402
from backend.triage.model import TriageModel  # noqa: E402

INVENTORY = ROOT / "data" / "poc" / "asset_inventory.yaml"


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """A fixture alert set and a model trained on it by the experiment script."""
    tmp = tmp_path_factory.mktemp("agent")
    make_raw_fixture.main(tmp / "raw")
    build_poc_alerts.main(["--raw-dir", str(tmp / "raw"), "--out", str(tmp / "set")])
    triage_experiment.main(["--data", str(tmp / "set"), "--out", str(tmp / "res"),
                            "--model-out", str(tmp / "model.joblib"), "--bootstrap", "10"])
    return tmp


def alert(**over):
    base = {"alert_id": "T-1", "timestamp": "2026-11-04T15:10:00Z", "rule_id": "R-NET-SCAN",
            "rule_name": "Port scan detected", "source_system": "network_ids",
            "description": "Host 198.51.100.9 probed web-prod-01 on ssh.", "src_ip": "198.51.100.9",
            "dst_ip": "10.10.2.10", "dst_port": 22, "protocol": "tcp", "service": "ssh", "host": "web-prod-01",
            "observables": {"packets": 400, "bytes_out": 24000, "bytes_in": 0, "duration_s": 3.1,
                            "packet_rate": 129.0}}
    base.update(over)
    return SocAlert(**base)


def test_agent_makes_the_same_decisions_the_experiment_measured(trained):
    """The agent and the experiment's hybrid approach must agree alert by alert."""
    agent = TriageAgent(INVENTORY, trained / "model.joblib", repeat_threshold=10**9)
    model = TriageModel.load(trained / "model.joblib", Context(Inventory(INVENTORY)))
    alerts = [json.loads(x) for x in (trained / "set" / "alerts_val.jsonl").read_text().splitlines()]
    expected = model.decide_all(alerts)
    for a, (cat, disp, conf, _, _) in zip(alerts, expected):
        d = agent.triage(SocAlert(**a))
        assert (d.category, d.disposition) == (cat, disp), a["alert_id"]
        assert d.confidence == pytest.approx(conf, abs=1e-3)


def test_approved_scan_is_benign_and_explained(trained):
    agent = TriageAgent(INVENTORY, trained / "model.joblib")
    # the approved scanner, inside its Tuesday 01:00-04:00 window, against a target subnet
    d = agent.triage(alert(timestamp="2026-11-03T02:15:00Z", src_ip="10.10.1.50", dst_ip="10.10.9.10",
                           host="dev-lab-01"))
    assert (d.category, d.disposition, d.severity) == ("B1", "BTP", "Informational")
    assert d.decided_by == "rules"
    assert "vuln-scan" in d.reasoning_summary


def test_without_a_model_the_rules_route_unclear_alerts_to_full(tmp_path):
    agent = TriageAgent(INVENTORY, tmp_path / "missing.joblib")
    d = agent.triage(alert(host="ws-eng-201", dst_ip="10.10.4.201"))
    assert d.decided_by == "rules_only_fallback"
    assert d.disposition == "TP" and d.investigation == "full"
    assert "low_confidence" in d.safeguards_fired


def test_unknown_host_is_treated_as_high_tier(tmp_path):
    agent = TriageAgent(INVENTORY, None)
    d = agent.triage(alert(host="laptop-unknown", dst_ip="10.10.77.7"))
    assert d.asset_tier == "High" and d.investigation == "full"
    assert "not in the asset inventory" in d.reasoning_summary


def test_unknown_rule_is_unclassified(trained):
    agent = TriageAgent(INVENTORY, trained / "model.joblib")
    d = agent.triage(alert(rule_id="R-CUSTOM-42"))
    assert (d.category, d.disposition, d.investigation) == ("U0", "needs_investigation", "full")


def test_repeat_source_safeguard_fires_on_the_nth_alert():
    agent = TriageAgent(INVENTORY, None, repeat_threshold=3, repeat_window_hours=24)
    fired = [("repeat_source" in agent.triage(alert(alert_id=f"T-{i}", timestamp=f"2026-11-04T1{i}:00:00Z"))
              .safeguards_fired) for i in range(4)]
    assert fired == [False, False, True, True]


def test_internal_ips_never_listed_as_external():
    d = TriageAgent(INVENTORY, None).triage(alert(src_ip="10.10.3.101"))
    assert "10.10.3.101" in d.indicators.internal_ips
    assert not any(ip.startswith("10.10.") for ip in d.indicators.external_ips)


def test_api_single_batch_legacy_names_and_validation():
    client = TestClient(app)
    body = alert().model_dump(mode="json", exclude_none=True)
    r = client.post("/api/v1/triage", json=body)
    assert r.status_code == 200 and r.json()["alert_id"] == "T-1"

    legacy = dict(body)
    legacy["source_ip"] = legacy.pop("src_ip")
    assert client.post("/api/v1/triage", json=legacy).json()["normalised_alert"]["src_ip"] == "198.51.100.9"

    r = client.post("/api/v1/triage/batch", json=[body, {**body, "alert_id": "T-2"}])
    assert [d["alert_id"] for d in r.json()] == ["T-1", "T-2"]

    broken = {k: v for k, v in body.items() if k != "rule_id"}
    r = client.post("/api/v1/triage", json=broken)
    assert r.status_code == 422 and "rule_id" in r.text
