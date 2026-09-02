import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from core.storage import ENGINE, DetectionRecord
from enterprise_app import app


def _seed(tenant: str) -> int:
    with Session(ENGINE) as session:
        from core.storage import set_tenant_context
        set_tenant_context(session, tenant)
        row = DetectionRecord(tenant_id=tenant, subject="sensor-host", source="correlation", detected=1, confidence="high", score=0.88, mitre_ttp="T1071", evidence_json='{"observed":true}', correlation_id=str(uuid.uuid4()), created_at=datetime.now(timezone.utc))
        session.add(row)
        session.flush()
        detection_id = row.id
        session.commit()
        return detection_id


def test_analyst_api_enforces_tenant_object_boundary(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "development")
    monkeypatch.setenv("THREATFADE_ALLOW_DEV_AUTH", "true")
    tenant_a = f"api-a-{uuid.uuid4().hex[:8]}"
    tenant_b = f"api-b-{uuid.uuid4().hex[:8]}"
    detection_id = _seed(tenant_a)
    client = TestClient(app)
    headers_a = {"X-Tenant-ID": tenant_a}
    headers_b = {"X-Tenant-ID": tenant_b}
    assert client.get("/enterprise/analyst/inbox", headers=headers_a).status_code == 200
    assert client.get(f"/enterprise/analyst/detections/{detection_id}", headers=headers_a).status_code == 200
    assert client.get(f"/enterprise/analyst/detections/{detection_id}", headers=headers_b).status_code == 404


def test_analyst_api_supports_detection_to_disposition(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "development")
    monkeypatch.setenv("THREATFADE_ALLOW_DEV_AUTH", "true")
    tenant = f"api-flow-{uuid.uuid4().hex[:8]}"
    detection_id = _seed(tenant)
    client = TestClient(app)
    headers = {"X-Tenant-ID": tenant}
    assert client.patch(f"/enterprise/analyst/detections/{detection_id}/workflow", headers=headers, json={"status": "investigating"}).status_code == 200
    case = client.post(f"/enterprise/analyst/detections/{detection_id}/cases", headers=headers, json={"title": "Investigate fade"})
    assert case.status_code == 200
    case_id = case.json()["id"]
    disposition = client.post(f"/enterprise/analyst/detections/{detection_id}/disposition", headers=headers, json={"reason": "true_positive", "note": "Evidence reviewed", "case_id": case_id})
    assert disposition.status_code == 200
    assert disposition.json()["reason"] == "true_positive"
