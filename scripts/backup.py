"""Create a portable, integrity-manifested PostgreSQL backup artifact.

The production continuity strategy uses provider-native PITR/WAL for low RPO and
this logical custom-format dump for portable disaster recovery and tenant/data
migration. The script never prints the database URL or credentials.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def create_backup(output_dir: Path) -> Path:
    database_url = os.environ.get("THREATFADE_DATABASE_URL")
    if not database_url:
        raise RuntimeError("THREATFADE_DATABASE_URL is required")
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = output_dir / f"threatfade-{stamp}.dump"
    # libpq accepts a URI via the final positional argument. The URI remains in
    # the process argument list briefly; CI must therefore use ephemeral secrets.
    _run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(archive), database_url])
    digest = sha256(archive.read_bytes()).hexdigest()
    toc = subprocess.run(["pg_restore", "--list", str(archive)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    if not toc.strip():
        raise RuntimeError("backup archive contains no restoreable objects")
    manifest = {
        "format": "postgresql-custom",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sha256": digest,
        "size_bytes": archive.stat().st_size,
        "postgresql_major": os.environ.get("THREATFADE_POSTGRES_MAJOR", "unknown"),
        "migration_head": os.environ.get("THREATFADE_MIGRATION_HEAD", "unknown"),
        "archive": archive.name,
    }
    (output_dir / f"{archive.stem}.manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"archive": archive.name, "sha256": digest, "size_bytes": archive.stat().st_size}, sort_keys=True))
    return archive


if __name__ == "__main__":
    create_backup(Path(sys.argv[1] if len(sys.argv) > 1 else "./backups"))
