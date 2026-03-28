#!/usr/bin/env python3
"""False-Positive Baseline Test for ThreatFade."""
import json
import random
import os
from datetime import datetime
from core.fade_engine import detect_fade

TOTAL_RUNS = 100
SIGNAL_LENGTH = 100

def gen_normal_browsing(n):
    return [0.6 + random.gauss(0, 0.08) for _ in range(n)]

def gen_steady_server(n):
    return [0.75 + random.gauss(0, 0.02) for _ in range(n)]

def gen_bursty_download(n):
    vals = []
    for i in range(n):
        if (i // 10) % 2 == 0:
            vals.append(0.9 + random.gauss(0, 0.03))
        else:
            vals.append(0.55 + random.gauss(0, 0.05))
    return vals

def gen_video_streaming(n):
    return [0.7 + random.gauss(0, 0.12) for _ in range(n)]

def gen_api_polling(n):
    vals = []
    for i in range(n):
        if i % 5 == 0:
            vals.append(0.8 + random.gauss(0, 0.03))
        else:
            vals.append(0.65 + random.gauss(0, 0.04))
    return vals

PATTERNS = [
    ("Normal browsing", gen_normal_browsing),
    ("Steady server", gen_steady_server),
    ("Bursty download", gen_bursty_download),
    ("Video streaming", gen_video_streaming),
    ("API polling", gen_api_polling),
]

def main():
    print("=" * 60)
    print("  ThreatFade False-Positive Baseline Test")
    print("=" * 60)
    results = []
    false_positives = 0
    total = 0
    runs_per = TOTAL_RUNS // len(PATTERNS)
    for name, fn in PATTERNS:
        fp = 0
        for _ in range(runs_per):
            vals = fn(SIGNAL_LENGTH)
            r = detect_fade(list(range(len(vals))), vals)
            total += 1
            if r["detected"]:
                false_positives += 1
                fp += 1
        rate = (fp / runs_per) * 100
        results.append({"pattern": name, "runs": runs_per, "false_positives": fp, "fp_rate_pct": round(rate, 1)})
        tag = "PASS" if rate < 15 else "WARN"
        print(f"  [{tag}] {name:20s}  FP: {fp}/{runs_per}  ({rate:.1f}%)")
    overall = (false_positives / total) * 100
    print(f"\n{'_' * 60}")
    print(f"  Overall false-positive rate: {false_positives}/{total} ({overall:.1f}%)")
    if overall < 10:
        print(f"  Verdict: GOOD (< 10%)")
    elif overall < 20:
        print(f"  Verdict: ACCEPTABLE (< 20%)")
    else:
        print(f"  Verdict: NEEDS WORK (>= 20%)")
    os.makedirs("reports", exist_ok=True)
    report = {"timestamp": datetime.now().isoformat(), "total_runs": total, "total_false_positives": false_positives, "overall_fp_rate_pct": round(overall, 1), "patterns": results}
    with open("reports/fp_baseline_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report saved: reports/fp_baseline_report.json")

if __name__ == "__main__":
    main()
