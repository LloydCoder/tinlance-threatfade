"""
ThreatFade Alert Deduplication
Prevents duplicate alerts for the same fade pattern.
Groups repeated detections within a time window.
"""

import time
import hashlib
import json
from typing import Dict, Any, Optional


class AlertDeduplicator:
    """
    Suppresses duplicate alerts within a configurable time window.
    Uses a hash of (confidence + mitre_ttp + fade_start) as the alert fingerprint.
    """

    def __init__(self, window_sec: int = 300, max_cache: int = 1000):
        self.window_sec = window_sec
        self.max_cache = max_cache
        self._cache: Dict[str, float] = {}

    def _fingerprint(self, result: Dict[str, Any], mitre_ttp: str) -> str:
        key = {
            "confidence": result.get("confidence", "info"),
            "mitre_ttp": mitre_ttp,
            "fade_start": result.get("fade_start", -1),
            "rules_matched": result.get("rules_matched", 0),
        }
        return hashlib.md5(
            json.dumps(key, sort_keys=True).encode()
        ).hexdigest()

    def _evict_expired(self):
        now = time.time()
        expired = [k for k, v in self._cache.items() if now - v > self.window_sec]
        for k in expired:
            del self._cache[k]

    def is_duplicate(self, result: Dict[str, Any], mitre_ttp: str) -> bool:
        if not result.get("detected", False):
            return False
        self._evict_expired()
        fp = self._fingerprint(result, mitre_ttp)
        if fp in self._cache:
            return True
        if len(self._cache) >= self.max_cache:
            oldest = min(self._cache, key=self._cache.get)
            del self._cache[oldest]
        self._cache[fp] = time.time()
        return False

    def suppress_or_alert(
        self,
        result: Dict[str, Any],
        mitre_ttp: str,
        source: str = "unknown"
    ) -> Dict[str, Any]:
        is_dup = self.is_duplicate(result, mitre_ttp)
        result["is_duplicate"] = is_dup
        result["suppressed"] = is_dup
        result["dedup_window_sec"] = self.window_sec
        if is_dup:
            result["suppression_reason"] = f"Duplicate alert within {self.window_sec}s window"
        return result

    def cache_size(self) -> int:
        self._evict_expired()
        return len(self._cache)

    def clear(self):
        self._cache.clear()
