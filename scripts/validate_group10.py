"""CI gate for Group 10 evaluation infrastructure.

This verifies contracts, split isolation, deterministic benchmarking and the
absence of unsupported independent-validation claims. It never treats a
synthetic benchmark as real-world validation.
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.group10_validation import run
from core.corpus import CorpusEntry, CorpusManifest
from core.evaluation import EvaluationCase
from core.evaluation_governance import EvaluationRun, evaluate_run


def demo_manifest() -> CorpusManifest:
    entries = tuple(
        CorpusEntry(
            sample_id=f"ci-{i}", dataset_id="group10-ci", dataset_version="1.0",
            split=split, source_type="synthetic", sha256=f"{i+1:064x}",
            content_format="flow-json", size_bytes=1, acquired_at="2026-08-22T00:00:00Z",
            source_reference="urn:threatfade:ci", license_reference="synthetic",
            label="fade" if i % 2 else "benign", label_confidence="confirmed",
        )
        for i, split in enumerate(("development", "tuning", "holdout", "blind"))
    )
    return CorpusManifest(
        corpus_id="group10-ci", version="1.0", purpose="CI contract validation",
        created_at="2026-08-22T00:00:00Z", entries=entries, owner="ThreatFade",
        methodology_reference="docs/evaluation/corpus-methodology.md", license_policy="synthetic-only",
    )


def main() -> None:
    corpus = demo_manifest()
    corpus.validate()
    result = evaluate_run(
        EvaluationRun(
            run_id="group10-ci-holdout", corpus_id=corpus.corpus_id, corpus_version=corpus.version,
            corpus_digest=corpus.digest(), detector_version="ci", detection_pack_version="ci",
            executed_at="2026-08-22T00:00:00Z", operator_reference="ci",
            environment_reference="github-actions", split="holdout", independent=False,
        ),
        [EvaluationCase("ci-2", "holdout", True, True, score=0.9)], corpus=corpus,
    )
    benchmark = run()
    if benchmark["benchmark"]["cases"] != 20000:
        raise AssertionError("Group 10 benchmark size is not fixed at the governed CI target")
    if "independent_validation" in result:
        raise AssertionError("synthetic evaluation must not claim independent validation")
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/group10-validation.json").write_text(json.dumps({"evaluation": result, "benchmark": benchmark}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Group 10 evaluation governance: OK")


if __name__ == "__main__":
    main()
