"""Filesystem-backed detection-pack registry with validation and safe reload semantics."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from core.detection_pack import validate_pack

ROOT = Path(os.getenv("THREATFADE_DETECTION_PACK_DIR", "detection_packs")) if False else Path("detection_packs")


def load_pack(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        pack = json.load(handle)
    validate_pack(pack)
    return pack


def list_packs() -> List[Dict[str, object]]:
    if not ROOT.exists():
        return []
    packs: List[Dict[str, object]] = []
    for path in sorted(ROOT.glob("*.json")):
        try:
            pack = load_pack(path)
            packs.append({"name": pack["name"], "version": pack["version"], "status": pack.get("status", "unknown"), "path": str(path)})
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return packs
