import pytest

from core.corpus import CorpusEntry, CorpusManifest, manifest_from_mapping, validate_split_separation


def entry(sample_id, split, digest):
    return CorpusEntry(
        sample_id=sample_id,
        dataset_id="threatfade-eval",
        dataset_version="1.0.0",
        split=split,
        source_type="synthetic",
        sha256=digest,
        content_format="jsonl",
        size_bytes=128,
        acquired_at="2026-08-22T00:00:00Z",
        source_reference="internal-fixture:synthetic-v1",
        license_reference="internal-license:research-only",
        label="fade",
        label_confidence="confirmed",
        attack_techniques=("T1071.001",),
        capture_environment="deterministic-test",
        capture_conditions={"seed": "42", "network": "isolated"},
    )


def test_entry_validates_provenance_and_attack_mapping():
    item = entry("sample-1", "development", "a" * 64)
    item.validate()
    assert item.canonical_dict()["sha256"] == "a" * 64


def test_manifest_digest_is_deterministic():
    manifest = CorpusManifest(
        corpus_id="threatfade-eval",
        version="1.0.0",
        purpose="Detection evaluation",
        created_at="2026-08-22T00:00:00Z",
        entries=(entry("sample-1", "development", "a" * 64), entry("sample-2", "blind", "b" * 64)),
        owner="ThreatFade Evaluation",
        methodology_reference="docs/evaluation/corpus-methodology.md",
        license_policy="review-before-use",
    )
    assert manifest.split_counts == {"blind": 1, "development": 1, "holdout": 0, "tuning": 0}
    assert len(manifest.digest()) == 64


def test_duplicate_hash_cannot_cross_splits():
    with pytest.raises(ValueError):
        validate_split_separation([entry("sample-1", "development", "a" * 64), entry("sample-2", "holdout", "a" * 64)])


def test_manifest_rejects_duplicate_sample_ids():
    manifest = CorpusManifest(
        corpus_id="x",
        version="1",
        purpose="test",
        created_at="2026-08-22T00:00:00Z",
        entries=(entry("same", "development", "a" * 64), entry("same", "development", "b" * 64)),
        owner="x",
        methodology_reference="x",
        license_policy="x",
    )
    with pytest.raises(ValueError):
        manifest.validate()


def test_blind_split_requires_governed_label_confidence():
    item = entry("sample-1", "blind", "a" * 64)
    invalid = CorpusEntry(**{**item.__dict__, "label_confidence": "unknown"})
    with pytest.raises(ValueError):
        invalid.validate()


def test_mapping_round_trip():
    source = entry("sample-1", "development", "a" * 64)
    manifest = {
        "corpus_id": "x",
        "version": "1",
        "purpose": "test",
        "created_at": "2026-08-22T00:00:00Z",
        "entries": [source.__dict__],
        "owner": "x",
        "methodology_reference": "x",
        "license_policy": "x",
    }
    parsed = manifest_from_mapping(manifest)
    assert parsed.entries[0].sample_id == "sample-1"
