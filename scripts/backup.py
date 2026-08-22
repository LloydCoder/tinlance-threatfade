"""Create a portable, integrity-manifested PostgreSQL logical backup artifact."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy.engine import make_url


def _pg_environment(database_url: str) -> tuple[list[str], dict[str, str]]:
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("THREATFADE_DATABASE_URL must use PostgreSQL")
    if not url.host or not url.database:
        raise RuntimeError("THREATFADE_DATABASE_URL must include host and database")
    args = ["--host", url.host, "--port", str(url.port or 5432), "--username", url.username or "", "--dbname", url.database]
    env = os.environ.copy()
    if url.password is not None:
        env["PGPASSWORD"] = url.password
    return args, env


def _run(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)


def create_backup(output_dir: Path) -> Path:
    database_url = os.environ.get("THREATFADE_DATABASE_URL")
    if not database_url:
        raise RuntimeError("THREATFADE_DATABASE_URL is required")
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = output_dir / f"threatfade-{stamp}.dump"
    pg_args, pg_env = _pg_environment(database_url)
    _run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(archive), *pg_args], pg_env)
    digest = sha256(archive.read_bytes()).hexdigest()
    toc = _run(["pg_restore", "--list", str(archive)]).stdout
    if not toc.strip():
        raise RuntimeError("backup archive contains no restoreable objects")
    manifest = {"format": "postgresql-custom", "created_at": datetime.now(timezone.utc).isoformat(), "sha256": digest, "size_bytes": archive.stat().st_size, "postgresql_major": os.environ.get("THREATFADE_POSTGRES_MAJOR", "unknown"), "migration_head": os.environ.get("THREATFADE_MIGRATION_HEAD", "unknown"), "archive": archive.name}
    (output_dir / f"{archive.stem}.manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"archive": archive.name, "sha256": digest, "size_bytes": archive.stat().st_size}, sort_keys=True))
    return archive

if __name__ == "__main__":
    create_backup(Path(sys.argv[1] if len(sys.argv) > 1 else "./backups"))
