"""Bounded durable sensor queue built on SQLite WAL.

The queue is local-only, bounded by both rows and bytes, and preserves FIFO
sequence numbers. It is intentionally independent of the control plane so a
sensor can continue collecting while disconnected.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from core.data_plane import SignalEvent


class DurableSensorQueue:
    def __init__(self, path: str, *, max_bytes: int = 256 * 1024 * 1024,
                 max_events: int = 100_000, retention_seconds: int = 7 * 86400):
        if max_bytes < 1 << 20 or max_bytes > 8 << 30:
            raise ValueError("max_bytes out of bounds")
        if not 1 <= max_events <= 10_000_000:
            raise ValueError("max_events out of bounds")
        if not 60 <= retention_seconds <= 90 * 86400:
            raise ValueError("retention_seconds out of bounds")
        self.path = str(Path(path))
        self.max_bytes = max_bytes
        self.max_events = max_events
        self.retention_seconds = retention_seconds
        self._lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, payload BLOB NOT NULL, created_at REAL NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")

    @staticmethod
    def _payload(event: SignalEvent) -> bytes:
        return event.canonical_bytes()

    def _usage(self, db) -> tuple[int, int]:
        row = db.execute("SELECT COUNT(*), COALESCE(SUM(length(payload)),0) FROM events").fetchone()
        return int(row[0]), int(row[1])

    def enqueue(self, event: SignalEvent, *, priority: int = 50) -> bool:
        if not isinstance(event, SignalEvent):
            raise TypeError("event required")
        if not isinstance(priority, int) or not 0 <= priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        payload = self._payload(event)
        now = time.time()
        with self._lock, self._connect() as db:
            if db.execute("SELECT 1 FROM events WHERE event_id=?", (event.event_id,)).fetchone():
                return True
            count, used = self._usage(db)
            if len(payload) > self.max_bytes:
                return False
            if count >= self.max_events or used + len(payload) > self.max_bytes:
                self._evict_expired(db, now)
                count, used = self._usage(db)
            if count >= self.max_events or used + len(payload) > self.max_bytes:
                return False
            db.execute("INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)", (event.event_id, payload, now))
            return True

    def _evict_expired(self, db, now: float) -> int:
        cutoff = now - self.retention_seconds
        cur = db.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
        return cur.rowcount

    def peek(self, limit: int = 100) -> list[tuple[int, bytes]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("invalid batch size")
        with self._lock, self._connect() as db:
            return [(int(s), bytes(p)) for s, p in db.execute("SELECT seq,payload FROM events ORDER BY seq LIMIT ?", (limit,))]

    def acknowledge(self, through_seq: int) -> int:
        if through_seq < 0:
            raise ValueError("invalid sequence")
        with self._lock, self._connect() as db:
            cur = db.execute("DELETE FROM events WHERE seq <= ?", (through_seq,))
            return cur.rowcount

    def replay(self, sender: Callable[[list[tuple[int, bytes]]], int], *, batch_size: int = 100) -> int:
        total = 0
        while True:
            batch = self.peek(batch_size)
            if not batch:
                return total
            ack = sender(batch)
            if ack < batch[0][0] or ack > batch[-1][0]:
                raise ValueError("sender returned invalid acknowledgement")
            self.acknowledge(ack)
            total += sum(1 for seq, _ in batch if seq <= ack)
            if ack < batch[-1][0]:
                return total

    def metrics(self) -> dict[str, int]:
        with self._lock, self._connect() as db:
            count, used = self._usage(db)
            return {"events": count, "bytes": used, "max_events": self.max_events, "max_bytes": self.max_bytes}
