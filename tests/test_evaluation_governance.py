from datetime import datetime, timezone

import pytest

from core.corpus import CorpusEntry, CorpusManifest
from core.evaluation import EvaluationCase
from core.evaluation_governance import EvaluationRun, evaluate_run, canonical_result_digest


def manifest():
    entries = tuple(
        CorpusEntry(
            sample_id=f"sample-{i}", dataset_id="tf-demo", dataset_version="1.0",
            split=split, source_type="synthetic", sha256=f"{i+1:064x}",
            content_format="flow-json", size_bytes=10, acquired_at="2026-08-22T00:00:00Z",
            source_reference="urn:test", license_reference="urn:license", label="fade",
            label_confidence="confirmed", attack_techniques=("T1071.001",),
        )
        for i, split in enumerate(("development", "tuning", "holdout", "blind"))
    )
    return CorpusManifest(
        corpus_id="tf-demo", version="1.0", purpose="test", created_at="2026-08-22T00:00:00Z",
        entries=entries, owner="security", methodology_reference="docs/evaluation/corpus-methodology.md",
        license_policy="synthetic-only",
    )


def run(split="holdout", independent=False):
    return EvaluationRun(
        run_id="run-1", corpus_id="tf-demo", corpus_version="1.0", corpus_digest=manifest().digest(),
        detector_version="0.9.0", detection_pack_version="1.0.0", executed_at="2026-08-22T00:00:00Z",
        operator_reference="test", environment_reference="ci", split=split, independent=independent,
    )


def test_holdout_evaluation_is_reproducible():
    cases = [EvaluationCase("sample-2", "holdout", True, True, score=0.9)]
    result = evaluate_run(run(), cases, corpus=manifest())
    assert result["metrics"]["recall"] == 1.0
    assert canonical_result_digest(result) == canonical_result_digest(result)


def test_blind_requires_independent_governance():
    cases = [EvaluationCase("sample-3", "blind", True, True, score=0.9)]
    with pytest.raises(PermissionError):
        evaluate_run(run("blind", False), cases, corpus=manifest())


def test_blind_accepts_independent_run():
    cases = [EvaluationCase("sample-3", "blind", True, True, score=0.9)]
    result = evaluate_run(run("blind", True), cases, corpus=manifest())
    assert result["run"]["independent"] is True


def test_cases_cannot_escape_governed_split():
    with pytest.raises(ValueError):
        evaluate_run(run(), [EvaluationCase("sample-0", "development", True, True)], corpus=manifest())
