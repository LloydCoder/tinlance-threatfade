"""Detection-pack registry primitives with immutable identity and lifecycle rules."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Mapping


LIFECYCLE = ("research", "validated", "canary", "production", "deprecated")
TRANSITIONS = {
    "research": {"validated"},
    "validated": {"canary", "research"},
    "canary": {"production", "validated"},
    "production": {"deprecated", "canary"},
    "deprecated": set(),
}


@dataclass(frozen=True)
class PackIdentity:
    pack_id: str
    version: str
    lifecycle: str
    content_sha256: str


def canonical_content(pack: Mapping[str, object]) -> bytes:
    return json.dumps(pack, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash(pack: Mapping[str, object]) -> str:
    return sha256(canonical_content(pack)).hexdigest()


def make_identity(pack: Mapping[str, object], pack_id: str, version: str, lifecycle: str = "research") -> PackIdentity:
    if not pack_id.strip() or not version.strip():
        raise ValueError("pack_id and version are required")
    if lifecycle not in LIFECYCLE:
        raise ValueError(f"unsupported lifecycle: {lifecycle}")
    return PackIdentity(pack_id, version, lifecycle, content_hash(pack))


def transition(identity: PackIdentity, target: str) -> PackIdentity:
    if target not in LIFECYCLE:
        raise ValueError(f"unsupported lifecycle: {target}")
    if target not in TRANSITIONS[identity.lifecycle]:
        raise ValueError(f"invalid lifecycle transition: {identity.lifecycle} -> {target}")
    return PackIdentity(identity.pack_id, identity.version, target, identity.content_sha256)


def verify_identity(pack: Mapping[str, object], identity: PackIdentity) -> bool:
    return content_hash(pack) == identity.content_sha256
