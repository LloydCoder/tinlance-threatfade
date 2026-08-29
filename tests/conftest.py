"""Safe, disposable database isolation for PostgreSQL-backed test runs.

When a PostgreSQL test URL is explicitly supplied, pytest creates a disposable
``threatfade_test_*`` database, upgrades it with the existing Alembic
migrations, and removes it at session end. Production application configuration
and production schemas are never modified.

Test workflows that do not provide a PostgreSQL URL intentionally keep the
repository's normal local SQLite behavior; this is required for lightweight
unit/governance workflows that do not provision PostgreSQL.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_DB_PREFIX = "threatfade_test_"


def _test_database_url() -> tuple[str, URL] | None:
    """Return a safe disposable PostgreSQL URL when one is configured."""
    explicit = os.getenv("TEST_DATABASE_URL")
    source = explicit or os.getenv("THREATFADE_DATABASE_URL")
    if not source:
        return None

    base = make_url(source)
    if base.get_backend_name() != "postgresql":
        # Some lightweight validation workflows intentionally use SQLite and
        # do not provision PostgreSQL. Preserve their existing behavior.
        return None

    if os.getenv("THREATFADE_ENV", "development").lower() == "production" and not explicit:
        pytest.exit("Refusing to derive a test database from a production database URL.")

    worker = os.getenv("PYTEST_XDIST_WORKER")
    suffix = f"_{worker}" if worker else ""

    if explicit:
        base_name = base.database or "threatfade_test"
        if not base_name.startswith(TEST_DB_PREFIX):
            base_name = f"{TEST_DB_PREFIX}{base_name}"
        name = f"{base_name}{suffix}"
    else:
        name = f"{TEST_DB_PREFIX.rstrip('_')}{suffix}" if worker else TEST_DB_PREFIX.rstrip("_")

    if not name.startswith(TEST_DB_PREFIX):
        pytest.exit("Refusing to use a database outside the threatfade_test_* namespace.")

    target = base.set(database=name)
    return target.render_as_string(hide_password=False), target


def _maintenance_url(target: URL) -> str:
    return target.set(database="postgres").render_as_string(hide_password=False)


def _database_exists(engine, name: str) -> bool:
    with engine.connect() as conn:
        return bool(
            conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            ).scalar()
        )


def _terminate_and_drop(engine, name: str) -> None:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) "
                "FROM pg_stat_activity "
                "WHERE datname = :name AND pid <> pg_backend_pid()"
            ),
            {"name": name},
        )
        conn.execute(text("DROP DATABASE IF EXISTS \"" + name.replace('"', '""') + "\""))


def _dispose_test_database(target: URL) -> None:
    name = target.database
    if not name or not name.startswith(TEST_DB_PREFIX):
        return
    maintenance = create_engine(_maintenance_url(target), pool_pre_ping=True)
    try:
        if _database_exists(maintenance, name):
            _terminate_and_drop(maintenance, name)
    finally:
        maintenance.dispose()


def pytest_sessionstart(session: pytest.Session) -> None:
    configured = _test_database_url()
    if configured is None:
        return

    url, target = configured
    name = target.database
    assert name is not None

    original_database_url = os.environ.get("THREATFADE_DATABASE_URL")
    original_test_database_url = os.environ.get("TEST_DATABASE_URL")
    session.config._threatfade_test_database = (
        target,
        original_database_url,
        original_test_database_url,
    )

    maintenance = create_engine(_maintenance_url(target), pool_pre_ping=True)
    try:
        if _database_exists(maintenance, name):
            _terminate_and_drop(maintenance, name)
        with maintenance.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("CREATE DATABASE \"" + name.replace('"', '""') + "\""))
    except Exception:
        try:
            _dispose_test_database(target)
        finally:
            maintenance.dispose()
        raise
    finally:
        maintenance.dispose()

    os.environ["THREATFADE_DATABASE_URL"] = url
    os.environ["TEST_DATABASE_URL"] = url

    try:
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=os.environ.copy(),
            check=True,
        )
    except Exception:
        _dispose_test_database(target)
        raise


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    value = getattr(session.config, "_threatfade_test_database", None)
    if not value:
        return

    target, original_database_url, original_test_database_url = value
    try:
        _dispose_test_database(target)
    finally:
        if original_database_url is None:
            os.environ.pop("THREATFADE_DATABASE_URL", None)
        else:
            os.environ["THREATFADE_DATABASE_URL"] = original_database_url

        if original_test_database_url is None:
            os.environ.pop("TEST_DATABASE_URL", None)
        else:
            os.environ["TEST_DATABASE_URL"] = original_test_database_url
