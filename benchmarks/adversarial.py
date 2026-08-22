"""Deterministic robustness checks for fade detection.

These are controlled signal perturbations, not claims about real attacker
success. They exist to catch brittle detector behavior before purple-team work.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.signal_generator import generate_signals
from core.fade_engine import detect_fade


PERTURBATIONS = {
    "baseline": lambda values: values,
    "jitter": lambda values: [max(0.0, float(v) + (0.015 if i % 2 else -0.015)) for i, v in enumerate(values)],
    "scale": lambda values: [max(0.0, min(1.0, float(v) * 0.92)) for v in values],
    "bounded_noise": lambda values: [max(0.0, min(1.0, float(v) + np.random.default_rng(9001 + i).normal(0.0, 0.02))) for i, v in enumerate(values)],
}

SCENARIOS = {"c2_quieting": True, "lotl_gradual": True, "gnss_jam": True, "normal_with_fade": False}


def run() -> dict:
    rows = []
    for scenario, expected in SCENARIOS.items():
        timestamps, values = generate_signals(scenario)
        for name, transform in PERTURBATIONS.items():
            perturbed = transform(values)
            result = detect_fade(timestamps, perturbed)
            rows.append({
                "scenario": scenario,
                "perturbation": name,
                "expected_detection": expected,
                "detected": bool(result["detected"]),
                "score": float(result["score"]),
            })
    return {"benchmark": "adversarial-synthetic-v1", "rows": rows}


def main() -> None:
    report = run()
    output = ROOT / "reports" / "benchmarks" / "adversarial-synthetic-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    for row in report["rows"]:
        if row["expected_detection"] and not row["detected"]:
            raise SystemExit(f"adversarial detection regression: {row}")
        if not row["expected_detection"] and row["detected"]:
            raise SystemExit(f"adversarial false-positive regression: {row}")


if __name__ == "__main__":
    main()
