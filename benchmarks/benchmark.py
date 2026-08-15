"""Reproducible benchmark harness for ThreatFade's deterministic scenarios."""
import json
import time
from pathlib import Path
from typing import Dict, List

import numpy as np

from agents.signal_generator import generate_signals
from core.fade_engine import detect_fade

SCENARIOS = {
    "c2_quieting": True,
    "lotl_gradual": True,
    "gnss_jam": True,
    "normal_with_fade": False,
    "mixed": True,
}


def run() -> Dict[str, object]:
    rows: List[Dict[str, object]] = []
    for index, (scenario, expected) in enumerate(SCENARIOS.items()):
        np.random.seed(index + 1)
        timestamps, values = generate_signals(scenario)
        start = time.perf_counter()
        result = detect_fade(timestamps, values)
        latency_ms = (time.perf_counter() - start) * 1000
        rows.append({
            "scenario": scenario,
            "expected_detection": expected,
            "detected": bool(result["detected"]),
            "correct": bool(result["detected"] == expected),
            "score": round(float(result["score"]), 6),
            "confidence": result["confidence"],
            "latency_ms": round(latency_ms, 4),
        })
    correct = sum(1 for row in rows if row["correct"])
    return {
        "tool": "ThreatFade",
        "benchmark": "synthetic-scenario-v1",
        "total": len(rows),
        "correct": correct,
        "accuracy": correct / len(rows) if rows else 0.0,
        "rows": rows,
    }


def main() -> None:
    report = run()
    out = Path("reports/benchmarks")
    out.mkdir(parents=True, exist_ok=True)
    (out / "synthetic-scenario-v1.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["accuracy"] < 1.0:
        raise SystemExit("Synthetic benchmark did not achieve expected scenario classification")


if __name__ == "__main__":
    main()
