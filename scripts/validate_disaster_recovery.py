"""Static acceptance gate for Group 6 disaster-recovery controls."""
from __future__ import annotations
from pathlib import Path

def main() -> None:
    root = Path(__file__).resolve().parents[1]
    backup = (root / "scripts/backup.py").read_text(encoding="utf-8")
    verify = (root / "scripts/restore_verify.py").read_text(encoding="utf-8")
    drill = (root / "scripts/restore_drill.py").read_text(encoding="utf-8")
    runbook = (root / "docs/DISASTER_RECOVERY.md").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    controls = [(backup, ["pg_dump", "--format=custom", "sha256", "PGPASSWORD", "migration_head"]),(verify,["pg_restore","sha256","restoreable_entries"]),(drill,["pg_restore","alembic_version","relforcerowsecurity","expected_revision"]),(runbook,["RPO","RTO","PITR","restore drill","encrypted","separate from the production database failure domain"]),(workflow,["validate_disaster_recovery.py","backup.py ./recovery-artifact","restore_verify.py","restore_drill.py","DROP DATABASE IF EXISTS threatfade_restore"])]
    for content, required in controls:
        missing = [item for item in required if item not in content]
        assert not missing, missing
    artifact_dir = root / "recovery-artifact"
    if artifact_dir.exists(): assert not any(p.name.endswith((".dump", ".backup", ".tar")) for p in artifact_dir.iterdir())
    print("Group 6 disaster recovery gate: OK")

if __name__ == "__main__": main()
