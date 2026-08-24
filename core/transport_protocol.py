"""Server-side persistence for the ThreatFade offline transport protocol."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .offline_transport import SigningKey


class DurableReplayLedger:
    """Persistent idempotency and monotonic-sequence state.

    Acceptance is atomic per tenant/sensor. Duplicate batch IDs are harmless;
    old sequences are rejected; gaps are surfaced for operational recovery.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS replay_batches (
            batch_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            first_sequence INTEGER NOT NULL,
            last_sequence INTEGER NOT NULL,
            accepted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS replay_cursors (
            tenant_id TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            last_sequence INTEGER NOT NULL,
            PRIMARY KEY(tenant_id, sensor_id)
        );
        """)

    def close(self) -> None:
        self.db.close()

    def accept(self, *, batch_id: str, tenant_id: str, sensor_id: str, first_sequence: int, last_sequence: int) -> str:
        if not batch_id or not tenant_id or not sensor_id or first_sequence < 1 or last_sequence < first_sequence:
            raise ValueError("invalid replay metadata")
        existing = self.db.execute("SELECT 1 FROM replay_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if existing:
            return "duplicate"
        row = self.db.execute("SELECT last_sequence FROM replay_cursors WHERE tenant_id=? AND sensor_id=?", (tenant_id, sensor_id)).fetchone()
        previous = int(row[0]) if row else 0
        if last_sequence <= previous:
            return "replay"
        if previous and first_sequence > previous + 1:
            return "gap"
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("INSERT INTO replay_batches VALUES(?,?,?,?,?,?)", (batch_id, tenant_id, sensor_id, first_sequence, last_sequence, now))
            self.db.execute("INSERT INTO replay_cursors VALUES(?,?,?) ON CONFLICT(tenant_id,sensor_id) DO UPDATE SET last_sequence=excluded.last_sequence", (tenant_id, sensor_id, last_sequence))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return "accepted"


class SigningTrustStore:
    """Local trust store supporting rotation and explicit revocation."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS signing_keys (key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, public_key_b64 TEXT NOT NULL, created_at TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL, revoked_at TEXT)")

    def close(self) -> None:
        self.db.close()

    def add(self, key: SigningKey) -> None:
        if key.revoked_at:
            raise ValueError("cannot add a revoked key")
        self.db.execute("INSERT OR REPLACE INTO signing_keys VALUES(?,?,?,?,?,?,?)", tuple(key.__dict__.values()))

    def revoke(self, key_id: str) -> None:
        if not self.db.execute("SELECT 1 FROM signing_keys WHERE key_id=?", (key_id,)).fetchone():
            raise KeyError(key_id)
        self.db.execute("UPDATE signing_keys SET revoked_at=? WHERE key_id=?", (datetime.now(timezone.utc).isoformat(), key_id))

    def get(self, key_id: str) -> SigningKey | None:
        row = self.db.execute("SELECT key_id,algorithm,public_key_b64,created_at,not_before,not_after,revoked_at FROM signing_keys WHERE key_id=?", (key_id,)).fetchone()
        return SigningKey(*row) if row else None

    def active_keys(self) -> Iterable[SigningKey]:
        rows = self.db.execute("SELECT key_id,algorithm,public_key_b64,created_at,not_before,not_after,revoked_at FROM signing_keys WHERE revoked_at IS NULL").fetchall()
        return [SigningKey(*row) for row in rows]
