"""PostgreSQL-only enterprise integrity acceptance gate."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.audit import append_event, export_jsonl, list_events, verify_events
from core.evidence import register_evidence, evidence_manifest, record_provenance
from core.storage import ENGINE, DetectionRecord, set_tenant_context

TENANT_A = "tenant-integrity-a"
TENANT_B = "tenant-integrity-b"


def main() -> None:
    if ENGINE.dialect.name != "postgresql":
        raise SystemExit("PostgreSQL is required for this gate")

    with Session(ENGINE) as session:
        session.execute(text("SELECT set_config('threatfade.tenant_id', :tenant, false)"), {"tenant": TENANT_A})
        session.add(DetectionRecord(
            tenant_id=TENANT_A, subject="integrity-test", source="ci", detected=1,
            confidence="high", score=0.9, mitre_ttp="T0000", evidence_json="{}",
            correlation_id="corr-a", created_at=datetime.now(timezone.utc),
        ))
        session.commit()

    with Session(ENGINE) as session:
        session.execute(text("SELECT set_config('threatfade.tenant_id', :tenant, false)"), {"tenant": TENANT_B})
        visible = session.query(DetectionRecord).all()
        assert visible == [], "RLS leaked tenant A data into tenant B"
        try:
            session.add(DetectionRecord(
                tenant_id=TENANT_A, subject="cross-tenant-write", source="ci", detected=1,
                confidence="high", score=0.9, mitre_ttp="T0000", evidence_json="{}",
                correlation_id="corr-b", created_at=datetime.now(timezone.utc),
            ))
            session.commit()
        except Exception:
            session.rollback()
        else:
            raise AssertionError("RLS allowed a cross-tenant write")

    event_a1 = append_event(tenant_id=TENANT_A, actor="ci", action="create", object_type="detection", object_id="1", outcome="success", correlation_id="corr-a")
    append_event(tenant_id=TENANT_A, actor="ci", action="inspect", object_type="detection", object_id="1", outcome="success", correlation_id="corr-a", before={"state": "open"}, after={"state": "investigating"})
    events = list_events(TENANT_A)
    assert verify_events(events)
    assert events[0].prev_hash == "0" * 64
    assert event_a1.event_hash == events[0].event_hash
    assert len(export_jsonl(TENANT_A).splitlines()) == 2

    evidence = register_evidence(tenant_id=TENANT_A, correlation_id="corr-a", evidence_type="pcap", media_type="application/octet-stream", content=b"threatfade-integrity", source_uri="ci://fixture")
    manifest = evidence_manifest(TENANT_A, "corr-a")
    assert manifest["manifest_sha256"] and manifest["items"][0]["sha256"] == evidence.content_sha256

    provenance = record_provenance(tenant_id=TENANT_A, correlation_id="corr-a", input_sha256=evidence.content_sha256, rule_pack_sha256="a" * 64, engine_version="0.4.0", config_sha256="b" * 64, model_sha256=None)
    assert provenance.provenance_sha256 and provenance.rule_pack_sha256 == "a" * 64

    print("PostgreSQL integrity gate: OK")


if __name__ == "__main__":
    main()
