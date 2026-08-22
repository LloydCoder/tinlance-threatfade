"""Reproducible detection-quality benchmark for ThreatFade synthetic scenarios.

This benchmark is intentionally separate from real-PCAP validation. It measures
classification quality across repeated deterministic seeds and reports a
confusion matrix, class-balanced metrics, scenario-level results, latency, and
bootstrap confidence intervals.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.signal_generator import generate_signals
from core.evaluation import EvaluationCase, evaluate_cases
from core.fade_engine import detect_fade

SCENARIOS = {
    "c2_quieting": True,
    "lotl_gradual": True,
    "gnss_jam": True,
    "normal_with_fade": False,
    "mixed": True,
}
RUNS_PER_SCENARIO = 100


def run() -> Dict[str, object]:
    cases: List[EvaluationCase] = []
    for scenario, expected in SCENARIOS.items():
        for run_number in range(RUNS_PER_SCENARIO):
            seed = (list(SCENARIOS).index(scenario) + 1) * 1000 + run_number
            np.random.seed(seed)
            timestamps, values = generate_signals(scenario)
            start = time.perf_counter()
            result = detect_fade(timestamps, values)
            latency_ms = (time.perf_counter() - start) * 1000
            cases.append(
                EvaluationCase(
                    case_id=f"synthetic-v2:{scenario}:{run_number:04d}",
                    scenario=scenario,
                    expected_detection=expected,
                    detected=bool(result["detected"]),
                    latency_ms=latency_ms,
                    score=float(result["score"]),
                )
            )

    report = evaluate_cases(cases, bootstrap=True)
    report.update(
        {
            "tool": "ThreatFade",
            "benchmark": "synthetic-scenario-v2",
            "runs_per_scenario": RUNS_PER_SCENARIO,
            "seed_scheme": "scenario_index*1000 + run_number",
            "scenario_labels": SCENARIOS,
        }
    )
    return report


def main() -> None:
    report = run()
    out = ROOT / "reports" / "benchmarks"
    out.mkdir(parents=True, exist_ok=True)
    (out / "synthetic-scenario-v2.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    metrics = report["metrics"]
    normal = report["scenarios"]["normal_with_fade"]
    malicious = [report["scenarios"][name] for name in SCENARIOS if SCENARIOS[name]]
    malicious_recall = min(row["recall"] for row in malicious)

    # Synthetic regression gate: all seeded malicious scenarios must remain
    # detectable and the known benign dip must remain free of false positives.
    if malicious_recall < 1.0:
        raise SystemExit(f"Synthetic detection recall regression: {malicious_recall:.4f}")
    if normal["false_positive_rate"] != 0.0:
        raise SystemExit(f"Synthetic false-positive regression: {normal['false_positive_rate']:.4f}")
    if metrics["support"] != len(SCENARIOS) * RUNS_PER_SCENARIO:
        raise SystemExit("Synthetic evaluation support count is inconsistent")


if __name__ == "__main__":
    main()
