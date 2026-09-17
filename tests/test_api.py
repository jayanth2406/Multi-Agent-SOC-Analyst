"""Integration tests for the FastAPI endpoints."""

from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def valid_alert() -> dict[str, object]:
    return {
        "alert_id": "API-001",
        "timestamp": "2026-09-17T14:20:00Z",
        "source_ip": "185.10.20.30",
        "destination_ip": "10.0.0.23",
        "user": "alice",
        "host": "host-23",
        "event_type": "authentication",
        "description": "20 failed SSH attempts followed by successful login",
        "failed_attempts": 20,
        "metadata": {"login_success_after_failures": True},
    }


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_triage_endpoint_returns_structured_result() -> None:
    response = client.post("/alerts/triage", json=valid_alert())

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == "API-001"
    assert body["category"] == "brute_force"
    assert body["classification"] == "likely_true_positive"
    assert body["severity"] == "high"
    assert "185.10.20.30" in body["extracted_iocs"]
    assert set(body) == {
        "alert_id",
        "classification",
        "category",
        "severity",
        "confidence",
        "reasoning_summary",
        "extracted_iocs",
        "required_investigations",
        "recommended_next_step",
    }


def test_invalid_alert_returns_validation_error() -> None:
    response = client.post("/alerts/triage", json={"alert_id": ""})

    assert response.status_code == 422


def test_rules_mode_works_without_llm_api_key() -> None:
    payload = valid_alert()
    payload["metadata"] = {}

    response = client.post("/alerts/triage", json=payload)

    assert response.status_code == 200
    assert response.json()["category"] == "brute_force"
