import pytest

from core.evaluation_corpus import CorpusCase, dataset_manifest, validate_corpus


def case(case_id, split="test", source_hash="a" * 64, duplicate_group=None):
    return CorpusCase(
        case_id=case_id,
        scenario="c2_quieting",
        label="malicious",
        label_confidence="high",
        split=split,
        source_id="sensor-1",
        source_type="pcap",
        source_sha256=source_hash,
        collection_start="2026-08-01T00:00:00Z",
        collection_end="2026-08-01T00:01:00Z",
        environment_id="lab-a",
        provenance="fixture://threatfade/test",
        adversarial=True,
        duplicate_group=duplicate_group,
    )


def test_valid_corpus_has_stable_manifest_hash():
    cases = [case("b"), case("a", source_hash="b" * 64)]
    report = validate_corpus(cases)
    assert report["valid"] is True
    first = dataset_manifest(cases, "threatfade-fixture", "1.0.0")
    second = dataset_manifest(list(reversed(cases)), "threatfade-fixture", "1.0.0")
    assert first["manifest_sha256"] == second["manifest_sha256"]


def test_same_source_cannot_cross_evaluation_splits():
    report = validate_corpus([case("train", "train"), case("test", "test")])
    assert report["valid"] is False
    assert any("crosses splits" in error for error in report["errors"])


def test_duplicate_group_cannot_cross_splits():
    report = validate_corpus([case("train", "train", source_hash="a" * 64, duplicate_group="dup-1"), case("test", "test", source_hash="b" * 64, duplicate_group="dup-1")])
    assert report["valid"] is False
    assert any("duplicate group" in error for error in report["errors"])


def test_timestamp_requires_timezone_and_order():
    invalid = case("bad")
    object.__setattr__(invalid, "collection_start", "2026-08-01T00:00:00")
    with pytest.raises(ValueError, match="timezone"):
        invalid.validate()


def test_source_hash_must_be_sha256():
    invalid = case("bad", source_hash="not-a-hash")
    with pytest.raises(ValueError, match="SHA-256"):
        invalid.validate()
