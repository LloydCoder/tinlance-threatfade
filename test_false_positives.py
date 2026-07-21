#!/usr/bin/env python3
"""False-Positive Baseline Test for ThreatFade — pytest format."""
import json
import random
import os
import pytest
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

@pytest.mark.parametrize("name,fn", PATTERNS)
def test_false_positive_baseline(name, fn):
    """Test that normal traffic patterns produce < 15% false positives."""
    fp = 0
    runs = TOTAL_RUNS // len(PATTERNS)
    for _ in range(runs):
        vals = fn(SIGNAL_LENGTH)
        r = detect_fade(list(range(len(vals))), vals)
        if r["detected"]:
            fp += 1
    rate = (fp / runs) * 100
    assert rate < 15, f"{name}: FP rate {rate:.1f}% >= 15%"

def test_overall_false_positive_rate():
    """Overall FP rate across all patterns must be < 10%."""
    false_positives = 0
    total = 0
    runs_per = TOTAL_RUNS // len(PATTERNS)
    for name, fn in PATTERNS:
        for _ in range(runs_per):
            vals = fn(SIGNAL_LENGTH)
            r = detect_fade(list(range(len(vals))), vals)
            total += 1
            if r["detected"]:
                false_positives += 1
    overall = (false_positives / total) * 100
    assert overall < 10, f"Overall FP rate {overall:.1f}% >= 10%"
