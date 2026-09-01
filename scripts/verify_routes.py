"""Fail-fast verification of the production application route composition."""

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

paths = {
    route.path
    for route in app.routes
    if getattr(route, "path", None)
}

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
