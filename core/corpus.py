"""Governed evaluation-corpus contracts for ThreatFade.

The corpus layer stores metadata and provenance, not malware payloads. It is
intended to make detection-evaluation evidence reproducible without coupling
ThreatFade to a particular repository, provider, or malware source.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Iterable, Mapping, Sequence


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SPLITS = frozenset({"development", "tuning", "holdout", "blind"})
SOURCE_TYPES = frozenset({"pcap", "flow", "synthetic", "sandbox", "purple_team", "other"})


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _required_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value.strip()


@dataclass(frozen=True)
class CorpusEntry:
    sample_id: str
    dataset_id: str
    dataset_version: str
    split: str
    source_type: str
    sha256: str
    content_format: str
    size_bytes: int
    acquired_at: str
    source_reference: str
    license_reference: str
    label: str
    label_confidence: str
    attack_techniques: tuple[str, ...] = field(default_factory=tuple)
    malware_family: str | None = None
    capture_environment: str | None = None
    capture_conditions: Mapping[str, str] = field(default_factory=dict)
    privacy_status: str = "reviewed"
    chain_of_custody_reference: str | None = None

    def validate(self) -> None:
        _required_text("sample_id", self.sample_id)
        _required_text("dataset_id", self.dataset_id)
        _required_text("dataset_version", self.dataset_version)
        _required_text("content_format", self.content_format)
        _required_text("source_reference", self.source_reference)
        _required_text("license_reference", self.license_reference)
        _required_text("label", self.label)
        if self.split not in SPLITS:
            raise ValueError(f"split must be one of {sorted(SPLITS)}")
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(f"unsupported source_type: {self.source_type}")
        if not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        if self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        _utc(self.acquired_at)
        if self.label_confidence not in {"confirmed", "high", "medium", "low", "unknown"}:
            raise ValueError("invalid label_confidence")
        if self.privacy_status not in {"reviewed", "restricted", "redacted", "unknown"}:
            raise ValueError("invalid privacy_status")
        if self.split == "blind" and self.label_confidence == "unknown":
            raise ValueError("blind evaluation entries require a governed label confidence")
        for technique in self.attack_techniques:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                raise ValueError(f"invalid ATT&CK technique identifier: {technique}")

    def canonical_dict(self) -> dict:
        self.validate()
        data = asdict(self)
        data["attack_techniques"] = sorted(self.attack_techniques)
        data["capture_conditions"] = dict(sorted(self.capture_conditions.items()))
        return data


@dataclass(frozen=True)
class CorpusManifest:
    corpus_id: str
    version: str
    purpose: str
    created_at: str
    entries: tuple[CorpusEntry, ...]
    owner: str
    methodology_reference: str
    license_policy: str
    restrictions: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        _required_text("corpus_id", self.corpus_id)
        _required_text("version", self.version)
        _required_text("purpose", self.purpose)
        _required_text("owner", self.owner)
        _required_text("methodology_reference", self.methodology_reference)
        _required_text("license_policy", self.license_policy)
        _utc(self.created_at)
        if not self.entries:
            raise ValueError("corpus must contain at least one entry")
        sample_ids: set[str] = set()
        hashes: dict[str, str] = {}
        for entry in self.entries:
            entry.validate()
            if entry.sample_id in sample_ids:
                raise ValueError(f"duplicate sample_id: {entry.sample_id}")
            sample_ids.add(entry.sample_id)
            previous = hashes.get(entry.sha256)
            if previous and previous != entry.split:
                raise ValueError(f"sample hash appears in multiple evaluation splits: {entry.sha256}")
            hashes[entry.sha256] = entry.split

    @property
    def split_counts(self) -> dict[str, int]:
        self.validate()
        counts = {split: 0 for split in sorted(SPLITS)}
        for entry in self.entries:
            counts[entry.split] += 1
        return counts

    def canonical_dict(self) -> dict:
        self.validate()
        return {
            "corpus_id": self.corpus_id,
            "version": self.version,
            "purpose": self.purpose,
            "created_at": _utc(self.created_at).isoformat(),
            "entries": [entry.canonical_dict() for entry in sorted(self.entries, key=lambda item: item.sample_id)],
            "owner": self.owner,
            "methodology_reference": self.methodology_reference,
            "license_policy": self.license_policy,
            "restrictions": sorted(self.restrictions),
        }

    def digest(self) -> str:
        canonical = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def validate_split_separation(entries: Sequence[CorpusEntry]) -> None:
    """Fail closed if a content hash crosses development/tuning/holdout/blind."""
    by_hash: dict[str, set[str]] = {}
    for entry in entries:
        entry.validate()
        by_hash.setdefault(entry.sha256, set()).add(entry.split)
    collisions = {digest: sorted(splits) for digest, splits in by_hash.items() if len(splits) > 1}
    if collisions:
        raise ValueError(f"evaluation split leakage detected: {collisions}")


def manifest_from_mapping(data: Mapping) -> CorpusManifest:
    entries = tuple(CorpusEntry(**entry) for entry in data.get("entries", []))
    manifest = CorpusManifest(
        corpus_id=data["corpus_id"],
        version=data["version"],
        purpose=data["purpose"],
        created_at=data["created_at"],
        entries=entries,
        owner=data["owner"],
        methodology_reference=data["methodology_reference"],
        license_policy=data["license_policy"],
        restrictions=tuple(data.get("restrictions", [])),
    )
    manifest.validate()
    return manifest
