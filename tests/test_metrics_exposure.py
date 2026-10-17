from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.observability import mount_metrics_if_enabled


def _metrics_app():
    metrics = FastAPI()

    @metrics.get("/")
    def scrape():
        return {"metrics": "test"}

    return metrics


def test_metrics_endpoint_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("THREATFADE_METRICS_ENABLED", raising=False)
    app = FastAPI()
    assert mount_metrics_if_enabled(app, _metrics_app()) is False
    response = TestClient(app).get("/metrics/")
    assert response.status_code == 404


def test_metrics_endpoint_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("THREATFADE_METRICS_ENABLED", "true")
    app = FastAPI()
    assert mount_metrics_if_enabled(app, _metrics_app()) is True
    response = TestClient(app).get("/metrics/")
    assert response.status_code == 200
    assert response.json() == {"metrics": "test"}


def test_metrics_endpoint_rejects_unrecognized_enable_values(monkeypatch):
    monkeypatch.setenv("THREATFADE_METRICS_ENABLED", "sometimes")
    app = FastAPI()
    assert mount_metrics_if_enabled(app, _metrics_app()) is False
    assert TestClient(app).get("/metrics/").status_code == 404
