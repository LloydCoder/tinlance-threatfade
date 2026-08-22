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

    required_backup_controls = [
        "pg_dump", "--format=custom", "sha256", "PGPASSWORD", "migration_head",
    ]
    required_verify_controls = ["pg_restore", "sha256", "restoreable_entries"]
    required_drill_controls = ["pg_restore", "alembic_version", "relforcerowsecurity", "expected_revision"]
    required_runbook_controls = ["RPO", "RTO", "PITR", "restore drill", "encrypted", "separate from the production database failure domain"]
    required_ci_controls = ["validate_disaster_recovery.py", "backup.py ./recovery-artifact", "restore_verify.py", "restore_drill.py", "DROP DATABASE IF EXISTS threatfade_restore"]

    for name, content, controls in (
        ("backup", backup, required_backup_controls),
        ("verification", verify, required_verify_controls),
        ("restore drill", drill, required_drill_controls),
        ("runbook", runbook, required_runbook_controls),
        ("CI", workflow, required_ci_controls),
    ):
        missing = [item for item in controls if item not in content]
        assert not missing, f"{name} missing controls: {missing}"

    assert not any(p.name.endswith((".dump", ".backup", ".tar")) for p in (root / "recovery-artifact").glob("*") ) if (root / "recovery-artifact").exists() else True
    print("Group 6 disaster recovery gate: OK")


if __name__ == "__main__":
    main()
