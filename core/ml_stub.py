"""
ThreatFade ML Stub — Isolation Forest Anomaly Detector
Lightweight ML layer for fade detection.
Runs on CPU, no GPU needed, works offline.

Usage:
    from core.ml_stub import MLDetector
    ml = MLDetector()
    ml.train(normal_signals)
    score, is_anomaly = ml.predict(test_signal)
"""

import os
import json
import numpy as np
from pathlib import Path

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


MODEL_DIR = Path("data/models")
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"


def is_ml_available():
    return ML_AVAILABLE


def extract_features(values):
    """Extract statistical features from a signal window."""
    arr = np.array(values, dtype=float)
    if len(arr) < 4:
        return np.zeros(8)

    # Rolling stats
    mean = np.mean(arr)
    std = np.std(arr)
    median = np.median(arr)
    skew = float(np.mean(((arr - mean) / (std + 1e-10)) ** 3))
    kurtosis = float(np.mean(((arr - mean) / (std + 1e-10)) ** 4) - 3)

    # Drop ratio
    drop_ratio = np.sum(arr < 0.5) / len(arr)

    # Max consecutive drops
    max_consec = 0
    current = 0
    for v in arr:
        if v < 0.5:
            current += 1
            max_consec = max(max_consec, current)
        else:
            current = 0

    # Entropy proxy (variance of differences)
    diffs = np.diff(arr)
    diff_var = np.var(diffs) if len(diffs) > 0 else 0.0

    return np.array([mean, std, median, skew, kurtosis, drop_ratio, max_consec, diff_var])


class MLDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.trained = False
        self._load_if_exists()

    def _load_if_exists(self):
        if not ML_AVAILABLE:
            return
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=UserWarning)
                    warnings.simplefilter("ignore", category=DeprecationWarning)
                    self.model = joblib.load(MODEL_PATH)
                    self.scaler = joblib.load(SCALER_PATH)
                    self.trained = True
            except Exception:
                self.trained = False

    def train(self, normal_signals_list):
        """Train on a list of normal signal arrays."""
        if not ML_AVAILABLE:
            return "scikit-learn not installed"

        features = []
        for signals in normal_signals_list:
            feat = extract_features(signals)
            features.append(feat)

        X = np.array(features)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=1,
        )
        self.model.fit(X_scaled)
        self.trained = True

        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        return f"Model trained on {len(features)} samples, saved to {MODEL_PATH}"

    def predict(self, values):
        """Predict anomaly score for a signal.
        Returns: (ml_score float 0-1, is_anomaly bool)
        """
        if not ML_AVAILABLE or not self.trained:
            return 0.0, False

        feat = extract_features(values).reshape(1, -1)
        feat_scaled = self.scaler.transform(feat)

        raw_score = self.model.decision_function(feat_scaled)[0]
        prediction = self.model.predict(feat_scaled)[0]

        # Convert to 0-1 range (lower decision_function = more anomalous)
        ml_score = max(0.0, min(1.0, 0.5 - (raw_score / 2)))

        is_anomaly = prediction == -1

        return float(ml_score), bool(is_anomaly)

    def train_from_generator(self, num_samples=200):
        """Auto-train using the built-in signal generator."""
        if not ML_AVAILABLE:
            return "scikit-learn not installed"

        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from agents.signal_generator import generate_signals

        normal_signals = []
        for _ in range(num_samples):
            _, vals = generate_signals("mixed")
            # Use only the non-fade portion as "normal"
            normal_signals.append(vals[:30])

        return self.train(normal_signals)
