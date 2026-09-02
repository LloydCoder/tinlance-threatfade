from api import app


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


def test_analyst_routes_are_registered():
    # FastAPI may represent included routers as internal wrapper routes in
    # ``app.routes``. OpenAPI exposes the effective application-level paths.
    paths = set(app.openapi().get("paths", {}))

    missing = EXPECTED_ANALYST_ROUTES - paths

    assert not missing, (
        "Analyst API router is not fully registered. "
        f"Missing routes: {sorted(missing)}"
    )
