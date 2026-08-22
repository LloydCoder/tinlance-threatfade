"""Fail-closed governance around ThreatFade evaluation runs.

This module orchestrates metadata already represented by ``core.corpus`` and
metrics in ``core.evaluation``. It deliberately stores references and hashes,
not malicious payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from core.corpus import CorpusEntry, CorpusManifest, validate_split_separation
from core.evaluation import EvaluationCase, evaluate_cases


@dataclass(frozen=True)
class EvaluationRun:
    run_id: str
    corpus_id: str
    corpus_version: str
    corpus_digest: str
    detector_version: str
    detection_pack_version: str
    executed_at: str
    operator_reference: str
    environment_reference: str
    split: str
    independent: bool = False

    def validate(self) -> None:
        fields = (self.run_id, self.corpus_id, self.corpus_version, self.corpus_digest,
                  self.detector_version, self.detection_pack_version,
                  self.operator_reference, self.environment_reference)
        if any(not isinstance(v, str) or not v.strip() for v in fields):
            raise ValueError("evaluation run metadata must be non-empty")
        if self.split not in {"development", "tuning", "holdout", "blind"}:
            raise ValueError("invalid evaluation split")
        if len(self.corpus_digest) != 64 or any(c not in "0123456789abcdef" for c in self.corpus_digest):
            raise ValueError("corpus_digest must be lowercase SHA-256")
        parsed = datetime.fromisoformat(self.executed_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("executed_at requires timezone")


def validate_corpus_for_evaluation(manifest: CorpusManifest, *, required_split: str) -> None:
    manifest.validate()
    if required_split not in {"development", "tuning", "holdout", "blind"}:
        raise ValueError("invalid required split")
    entries = list(manifest.entries)
    validate_split_separation(entries)
    selected = [e for e in entries if e.split == required_split]
    if not selected:
        raise ValueError(f"corpus has no {required_split} entries")
    if required_split in {"holdout", "blind"}:
        if any(e.label_confidence == "unknown" for e in selected):
            raise ValueError(f"{required_split} evaluation cannot contain unknown labels")


def evaluate_run(run: EvaluationRun, cases: Sequence[EvaluationCase], *, corpus: CorpusManifest) -> dict:
    run.validate()
    validate_corpus_for_evaluation(corpus, required_split=run.split)
    case_ids = {case.case_id for case in cases}
    corpus_ids = {entry.sample_id for entry in corpus.entries if entry.split == run.split}
    if not case_ids.issubset(corpus_ids):
        raise ValueError("evaluation cases contain samples outside the governed corpus split")
    if len(case_ids) != len(cases):
        raise ValueError("duplicate evaluation case identifiers")
    if run.split == "blind" and not run.independent:
        raise PermissionError("blind runs must be independently governed")
    result = evaluate_cases(cases)
    result["run"] = asdict(run)
    result["corpus"] = {"corpus_id": corpus.corpus_id, "version": corpus.version, "digest": corpus.digest()}
    return result


def canonical_result_digest(result: Mapping) -> str:
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def write_evaluation_result(path: str | Path, result: Mapping) -> str:
    digest = canonical_result_digest(result)
    document = {"schema_version": "1", "result": result, "result_digest": digest}
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return digest
