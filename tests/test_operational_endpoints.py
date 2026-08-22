from fastapi.testclient import TestClient

from enterprise_app import app


def test_operational_endpoints():
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/startup").status_code == 200
        ready = client.get("/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "threatfade_http_requests_total" in metrics.text


def test_readiness_reports_storage():
    with TestClient(app) as client:
        payload = client.get("/ready").json()
        assert payload["checks"]["storage"]["status"] == "ok"
        assert payload["checks"]["dashboard"]["status"] == "ok"
