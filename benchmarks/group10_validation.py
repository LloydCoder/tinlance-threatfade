"""Deterministic Group 10 evaluation harness.

The harness uses abstract labeled signals rather than executable malware. It is
safe to run in CI and is intended to validate the evaluation machinery and
robustness of detector decisions before real governed corpora are introduced.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import random
import time

from core.evaluation import EvaluationCase, evaluate_cases


@dataclass(frozen=True)
class Scenario:
    name: str
    truth: bool
    base_score: float
    jitter: float
    packet_loss: float
    burstiness: float


def make_cases(size: int = 20000, seed: int = 20260822) -> list[EvaluationCase]:
    rng = random.Random(seed)
    cases: list[EvaluationCase] = []
    for i in range(size):
        positive = (i % 5) != 0
        score = (0.78 if positive else 0.18) + rng.uniform(-0.12, 0.12)
        score = max(0.0, min(1.0, score))
        predicted = score >= 0.5
        cases.append(EvaluationCase(f"synthetic-{i:06d}", "synthetic", positive, predicted, score=score))
    return cases


def robustness_scenarios() -> list[Scenario]:
    return [
        Scenario("baseline", True, 0.80, 0.00, 0.00, 0.50),
        Scenario("timing-jitter", True, 0.72, 0.25, 0.00, 0.45),
        Scenario("packet-loss", True, 0.67, 0.05, 0.20, 0.40),
        Scenario("burst-splitting", True, 0.65, 0.35, 0.05, 0.30),
        Scenario("benign-noise", False, 0.22, 0.20, 0.05, 0.65),
    ]


def run() -> dict:
    cases = make_cases()
    started = time.perf_counter()
    result = evaluate_cases(cases, bootstrap=False)
    elapsed = time.perf_counter() - started
    result["benchmark"] = {"cases": len(cases), "elapsed_seconds": elapsed, "seed": 20260822}
    result["robustness_scenarios"] = [scenario.__dict__ for scenario in robustness_scenarios()]
    if result["metrics"]["support"] != 20000:
        raise AssertionError("benchmark support mismatch")
    if not math.isfinite(result["metrics"]["f1"]):
        raise AssertionError("non-finite benchmark metric")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
