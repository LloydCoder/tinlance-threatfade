"""Fail-fast verification of the production application route composition."""

import sys
from pathlib import Path

# Allow this script to be executed directly from the repository root or from
# inside the Docker image without relying on the caller's PYTHONPATH.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enterprise_app import app


EXPECTED_ANALYST_ROUTES = {
    "/enterprise/analyst/inbox",
    "/enterprise/analyst/detections/{detection_id}",
    "/enterprise/analyst/detections/{detection_id}/workflow",
    "/enterprise/analyst/detections/{detection_id}/timeline",
    "/enterprise/analyst/detections/{detection_id}/cases",
    "/enterprise/analyst/detections/{detection_id}/disposition",
    "/enterprise/analyst/detections/{detection_id}/entities",
    "/enterprise/analyst/detections/{detection_id}/sessions",
}

# FastAPI may represent included routers as internal wrapper routes in
# ``app.routes``. OpenAPI exposes the effective application-level paths.
paths = set(app.openapi().get("paths", {}))

missing = EXPECTED_ANALYST_ROUTES - paths

print(f"TOTAL ROUTES: {len(paths)}")
print(f"ANALYST ROUTES: {len(paths & EXPECTED_ANALYST_ROUTES)}")

for path in sorted(paths & EXPECTED_ANALYST_ROUTES):
    print(f"  OK {path}")

if missing:
    print("\nMISSING ANALYST ROUTES:")
    for path in sorted(missing):
        print(f"  MISSING {path}")
    raise SystemExit(1)

print("\nROUTE COMPOSITION: PASS")
