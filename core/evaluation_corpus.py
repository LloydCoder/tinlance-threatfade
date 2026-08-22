"""Ground-truth corpus contracts for reproducible ThreatFade evaluation.

The corpus layer deliberately separates dataset identity/provenance from detector
results. It prevents accidental train/tune/test leakage and makes evaluation
inputs auditable without requiring raw PCAPs to live in the repository.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable, Sequence


ALLOWED_LABELS = {"malicious", "benign", "unknown"}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
ALLOWED_SPLITS = {"train", "tune", "test", "holdout"}


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    scenario: str
    label: str
    label_confidence: str
    split: str
    source_id: str
    source_type: str
    source_sha256: str
    collection_start: str
    collection_end: str
    environment_id: str
    provenance: str
    adversarial: bool = False
    duplicate_group: str | None = None
    notes: str = ""

    def validate(self) -> None:
        if not self.case_id.strip():
            raise ValueError("case_id must not be empty")
        if self.label not in ALLOWED_LABELS:
            raise ValueError(f"unsupported label: {self.label}")
        if self.label_confidence not in ALLOWED_CONFIDENCE:
            raise ValueError(f"unsupported label confidence: {self.label_confidence}")
        if self.split not in ALLOWED_SPLITS:
            raise ValueError(f"unsupported split: {self.split}")
        if len(self.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.source_sha256.lower()):
            raise ValueError("source_sha256 must be a 64-character hexadecimal SHA-256")
        if not self.source_id.strip() or not self.environment_id.strip() or not self.provenance.strip():
            raise ValueError("source_id, environment_id and provenance are required")
        _parse_timestamp(self.collection_start)
        _parse_timestamp(self.collection_end)
        if _parse_timestamp(self.collection_end) < _parse_timestamp(self.collection_start):
            raise ValueError("collection_end must not precede collection_start")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def validate_corpus(cases: Iterable[CorpusCase]) -> dict:
    materialized = list(cases)
    errors: list[str] = []
    ids: set[str] = set()
    source_hashes: dict[str, list[CorpusCase]] = {}
    duplicate_groups: dict[str, list[CorpusCase]] = {}

    for case in materialized:
        try:
            case.validate()
        except ValueError as exc:
            errors.append(f"{case.case_id}: {exc}")
        if case.case_id in ids:
            errors.append(f"duplicate case_id: {case.case_id}")
        ids.add(case.case_id)
        source_hashes.setdefault(case.source_sha256, []).append(case)
        if case.duplicate_group:
            duplicate_groups.setdefault(case.duplicate_group, []).append(case)

    # A raw source hash must not cross evaluation partitions. Near-duplicates are
    # explicitly grouped so the same source cannot leak between train/tune/test.
    for source_hash, group in source_hashes.items():
        splits = {case.split for case in group}
        if len(splits) > 1:
            errors.append(f"source hash {source_hash} crosses splits: {sorted(splits)}")
    for duplicate_group, group in duplicate_groups.items():
        splits = {case.split for case in group}
        if len(splits) > 1:
            errors.append(f"duplicate group {duplicate_group} crosses splits: {sorted(splits)}")

    label_counts = {label: sum(case.label == label for case in materialized) for label in sorted(ALLOWED_LABELS)}
    split_counts = {split: sum(case.split == split for case in materialized) for split in sorted(ALLOWED_SPLITS)}
    return {
        "valid": not errors,
        "case_count": len(materialized),
        "label_counts": label_counts,
        "split_counts": split_counts,
        "unique_sources": len(source_hashes),
        "errors": errors,
    }


def dataset_manifest(cases: Sequence[CorpusCase], dataset_id: str, version: str) -> dict:
    if not dataset_id.strip() or not version.strip():
        raise ValueError("dataset_id and version are required")
    validation = validate_corpus(cases)
    if not validation["valid"]:
        raise ValueError("cannot create manifest from invalid corpus")
    ordered = sorted(cases, key=lambda case: case.case_id)
    canonical = "\n".join(
        f"{case.case_id}|{case.source_sha256}|{case.label}|{case.split}|{case.environment_id}"
        for case in ordered
    ).encode("utf-8")
    return {
        "dataset_id": dataset_id,
        "version": version,
        "manifest_sha256": sha256(canonical).hexdigest(),
        "case_count": len(ordered),
        "validation": validation,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": [case.to_dict() for case in ordered],
    }
