"""Deterministic benchmark for the Detection Science 2.0 evidence layer.

This benchmark is deliberately synthetic. It measures regression behavior of the
implementation; it is not independent validation or a claim about production
false-positive/negative rates.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.evaluation import EvaluationCase, evaluate_cases
from core.fade_engine import detect_fade


def scenarios():
    return {
        "c2_quieting": ([0.8] * 20 + [0.08] * 50 + [0.65] * 30, True),
        "lotl_gradual": ([0.9 - i * 0.008 for i in range(100)], True),
        "gnss_like_disruption": ([0.85] * 25 + [0.1] * 45 + [0.65] * 30, True),
        "stable": ([0.8] * 100, False),
        "brief_benign_dip": ([0.75] * 40 + [0.4] * 9 + [0.75] * 51, False),
        "normal_jitter": ([0.75 + (0.03 if i % 2 else -0.03) for i in range(100)], False),
    }


def run() -> dict:
    cases = []
    for name, (values, expected) in scenarios().items():
        result = detect_fade(list(range(len(values))), values)
        cases.append(EvaluationCase(name, name, expected, bool(result["detected"]), score=float(result["score"])))
    return {
        "benchmark": "detection-science-v2-synthetic-v1",
        "evaluation": evaluate_cases(cases, bootstrap=True),
        "cases": [
            {"case_id": c.case_id, "scenario": c.scenario, "expected_detection": c.expected_detection, "detected": c.detected, "score": c.score}
            for c in cases
        ],
    }


def main() -> None:
    report = run()
    output = ROOT / "reports" / "benchmarks" / "detection-science-v2-synthetic-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    metrics = report["evaluation"]["metrics"]
    print(json.dumps(report, indent=2))
    if metrics["false_positive"] != 0:
        raise SystemExit(f"synthetic false-positive regression: {metrics}")
    if metrics["false_negative"] != 0:
        raise SystemExit(f"synthetic false-negative regression: {metrics}")


if __name__ == "__main__":
    main()
