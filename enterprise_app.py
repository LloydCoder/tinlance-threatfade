"""Production application entrypoint.

The legacy ``api:app`` remains available for compatibility. Production deployments
use this wrapper so enterprise analyst routes are always mounted explicitly.
"""
from api import app
from core.enterprise_routes import router as enterprise_router

app.include_router(enterprise_router)
