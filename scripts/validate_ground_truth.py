"""Validate a JSONL ground-truth corpus and emit a deterministic summary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.evaluation_corpus import CorpusCase, validate_corpus


def load(path: Path) -> list[CorpusCase]:
    cases = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            cases.append(CorpusCase(**json.loads(raw)))
        except (TypeError, json.JSONDecodeError, ValueError) as exc:
            raise SystemExit(f"{path}:{line_number}: invalid corpus record: {exc}") from exc
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default="datasets/fixtures/ground_truth_v1.jsonl")
    args = parser.parse_args()
    report = validate_corpus(load(Path(args.path)))
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["valid"]:
        raise SystemExit("ground-truth corpus validation failed")
    if report["case_count"] == 0:
        raise SystemExit("ground-truth corpus must not be empty")


if __name__ == "__main__":
    main()
