from datetime import datetime, timezone
import uuid

from sqlalchemy.orm import Session

from core.analyst import create_case_for_detection, dispose, inbox, set_workflow, timeline
from core.storage import ENGINE, DetectionRecord, set_tenant_context


def _seed(tenant: str) -> int:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant)
        row = DetectionRecord(
            tenant_id=tenant,
            subject="host-1",
            source="test",
            detected=1,
            confidence="high",
            score=0.91,
            mitre_ttp="T1071",
            evidence_json='{"signal":"fade"}',
            correlation_id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        detection_id = row.id
        session.commit()
        return detection_id


def test_detection_workflow_is_tenant_scoped():
    a = f"phase3-a-{uuid.uuid4().hex[:8]}"
    b = f"phase3-b-{uuid.uuid4().hex[:8]}"
    detection_id = _seed(a)
    assert set_workflow(a, detection_id, "analyst-a", status="triaging", assignee="analyst-a", priority=80)
    assert inbox(a)[0][0].id == detection_id
    assert inbox(b) == []


def test_detection_to_case_to_disposition_and_timeline():
    tenant = f"phase3-flow-{uuid.uuid4().hex[:8]}"
    detection_id = _seed(tenant)
    set_workflow(tenant, detection_id, "analyst", status="investigating")
    case = create_case_for_detection(tenant, detection_id, "analyst", "Investigate fade")
    assert case is not None
    disposition = dispose(tenant, detection_id, "analyst", "true_positive", "Observed matching evidence", case.id)
    assert disposition.reason == "true_positive"
    events = timeline(tenant, detection_id)
    assert any(item["kind"] == "case_event" and item["event_type"] == "detection.disposition" for item in events)


def test_invalid_workflow_and_disposition_are_rejected():
    tenant = f"phase3-invalid-{uuid.uuid4().hex[:8]}"
    detection_id = _seed(tenant)
    try:
        set_workflow(tenant, detection_id, "analyst", status="admin")
        assert False, "invalid status accepted"
    except ValueError:
        pass
    try:
        dispose(tenant, detection_id, "analyst", "malicious")
        assert False, "invalid disposition accepted"
    except ValueError:
        pass
