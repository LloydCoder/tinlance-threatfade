"""Restore a ThreatFade logical backup into an isolated database and verify it."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

def _pg_args(database_url: str) -> tuple[list[str], dict[str, str]]:
    import os
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql" or not url.host or not url.database: raise RuntimeError("database URL must be a complete PostgreSQL URL")
    env = os.environ.copy()
    if url.password is not None: env["PGPASSWORD"] = url.password
    return ["--host", url.host, "--port", str(url.port or 5432), "--username", url.username or "", "--dbname", url.database], env

def restore_and_verify(archive: Path, target_url: str, expected_revision: str) -> dict[str, object]:
    if not archive.is_file() or archive.stat().st_size == 0: raise ValueError("backup archive is missing or empty")
    args, env = _pg_args(target_url)
    subprocess.run(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", *args, str(archive)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    engine = create_engine(target_url)
    required = {"detections", "cases", "audit_events", "evidence", "provenance", "investigation_timeline"}
    with engine.connect() as conn:
        revision = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar_one()
        if revision != expected_revision: raise RuntimeError(f"restored migration head {revision!r} != expected {expected_revision!r}")
        tables = set(inspect(conn).get_table_names()); missing = sorted(required - tables)
        if missing: raise RuntimeError(f"restored database missing required tables: {missing}")
        rows = conn.execute(text("SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND relname = ANY(:tables)"), {"tables": list(required)}).all()
        rls = {row[0]: bool(row[1] and row[2]) for row in rows}
        if set(rls) != required or not all(rls.values()): raise RuntimeError(f"restored tenant tables do not all have forced RLS enabled: {rls}")
    return {"status": "ok", "migration_head": revision, "tables": len(tables), "rls_tables": len(rls)}

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("archive", type=Path); parser.add_argument("--target-url", required=True); parser.add_argument("--expected-revision", required=True)
    args = parser.parse_args(); print(restore_and_verify(args.archive, args.target_url, args.expected_revision))

if __name__ == "__main__": main()
