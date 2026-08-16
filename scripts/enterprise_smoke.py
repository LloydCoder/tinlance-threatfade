"""Fast, dependency-light enterprise readiness smoke checks for CI."""
from pathlib import Path


def _route_paths(routes):
    paths = set()
    for route in routes:
        path = getattr(route, "path", None)
        if path:
            paths.add(path)
        nested = getattr(route, "routes", None)
        if nested:
            paths.update(_route_paths(nested))
    return paths


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        "README.md", "SECURITY.md", "Dockerfile", "docker-compose.yml",
        "docs/ENTERPRISE_READINESS.md", "docs/THREAT_MODEL.md", "docs/CONTROL_MATRIX.md",
        "dashboard/index.html", ".github/workflows/ci.yml", ".github/workflows/security.yml",
        "enterprise_app.py", "core/enterprise_routes.py", "detection_packs/core-1.0.0.json",
    ]
    missing = [p for p in required if not (root / p).exists()]
    if missing:
        raise SystemExit(f"enterprise smoke failed; missing: {missing}")

    dashboard = (root / "dashboard/index.html").read_text(encoding="utf-8")
    for marker in ("ThreatFade Dashboard", "/health", "/detect/scenario"):
        if marker not in dashboard:
            raise SystemExit(f"dashboard smoke failed; missing marker: {marker}")

    import sys
    sys.path.insert(0, str(root))
    import enterprise_app
    routes = _route_paths(enterprise_app.app.routes)
    expected = {
        "/", "/health", "/ready", "/version", "/detect",
        "/detect/pcap", "/detect/scenario",
        "/enterprise/detections/{detection_id}/feedback", "/enterprise/feedback",
        "/enterprise/cases", "/enterprise/cases/{case_id}",
        "/enterprise/cases/{case_id}/comments", "/enterprise/cases/{case_id}/timeline",
    }
    if not expected.issubset(routes):
        raise SystemExit(f"API smoke failed; missing routes: {sorted(expected - routes)}")

    from core.detection_registry import list_packs
    if not list_packs():
        raise SystemExit("detection registry smoke failed; no valid packs found")
    print("enterprise smoke: OK")


if __name__ == "__main__":
    main()
