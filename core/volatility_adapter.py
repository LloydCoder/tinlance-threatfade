"""Optional Volatility 3 adapter for memory-artifact enrichment.

The adapter is deliberately optional: ThreatFade remains usable when Volatility 3
is not installed. When available, callers can pass a memory image and receive a
stable summary suitable for alert evidence.
"""
from pathlib import Path
from typing import Any, Dict


def analyze_memory(image_path: str) -> Dict[str, Any]:
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Memory image not found: {image_path}")
    try:
        import volatility3  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("Volatility 3 is not installed; install the optional memory-analysis dependency") from exc
    return {
        "available": True,
        "image": str(path),
        "size_bytes": path.stat().st_size,
        "engine": "volatility3",
        "status": "ready",
    }
