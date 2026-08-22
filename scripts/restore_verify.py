"""Verify a ThreatFade PostgreSQL backup without touching production."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
import json
import subprocess
import sys

def verify_backup(archive: Path, manifest: Path | None = None) -> dict[str, object]:
    if not archive.is_file() or archive.stat().st_size == 0: raise ValueError("backup archive is missing or empty")
    digest = sha256(archive.read_bytes()).hexdigest()
    if manifest:
        expected = json.loads(manifest.read_text(encoding="utf-8"))["sha256"]
        if digest != expected: raise ValueError("backup SHA-256 does not match its manifest")
    listing = subprocess.run(["pg_restore", "--list", str(archive)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    entries = [line for line in listing.splitlines() if line and not line.startswith(";")]
    if not entries: raise ValueError("backup has no restoreable entries")
    return {"sha256": digest, "restoreable_entries": len(entries), "archive": archive.name}

if __name__ == "__main__":
    archive = Path(sys.argv[1]); manifest = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    print(json.dumps(verify_backup(archive, manifest), sort_keys=True))
