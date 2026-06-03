"""
IntelliSecure - Unified FastAPI Application
==========================================
AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System
Version 2.0.0

This is the canonical application entry point.
Run via: python run.py  (from project root)
Or:      uvicorn backend.app_old:app --reload  (from project root)

Author: IntelliSecure Team
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from .config   import settings
from .database import engine, Base

# â”€â”€â”€ Model registration (must import BEFORE create_all) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from .models import User, LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog, Alert

# â”€â”€â”€ API Routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from .api.auth_routes      import router as auth_router
from .api.log_routes       import router as log_router
from .api.threat_routes    import router as threat_router
from .api.score_routes     import router as score_router
from .api.dashboard_routes import router as dashboard_router
from .api.device_routes    import router as device_router
from .api.report_routes    import router as report_router

# â”€â”€â”€ DB Table Creation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Base.metadata.create_all(bind=engine)

# â”€â”€â”€ FastAPI App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System. "
        "Features: real-time threat monitoring, multi-source log correlation, "
        "explainable AI, automated PDF/PPT reporting, and LAN device discovery."
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# â”€â”€â”€ CORS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# â”€â”€â”€ Mount All Routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.include_router(auth_router,      prefix="/api/auth",      tags=["Authentication"])
app.include_router(log_router,       prefix="/api/logs",      tags=["Logs"])
app.include_router(threat_router,    prefix="/api/threats",   tags=["Threats"])
app.include_router(score_router,     prefix="/api/score",     tags=["Security Score"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(device_router,    prefix="/api/devices",   tags=["LAN Devices"])
app.include_router(report_router,    prefix="/api/reports",   tags=["Reports"])

# â”€â”€â”€ Static Assets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR     = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

for sub in ["css", "js", "assets"]:
    os.makedirs(os.path.join(FRONTEND_DIR, sub), exist_ok=True)

app.mount("/css",    StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")),    name="css")
app.mount("/js",     StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")),     name="js")
app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

# â”€â”€â”€ Page Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/", include_in_schema=False)
@app.get("/login", include_in_schema=False)
def serve_login():
    """Serve the login / registration page."""
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))

@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    """Serve the main SPA dashboard."""
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/alerts", include_in_schema=False)
def serve_alerts_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "alerts.html"))

@app.get("/devices", include_in_schema=False)
def serve_devices_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "devices.html"))

@app.get("/reports", include_in_schema=False)
def serve_reports_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "reports.html"))

# â”€â”€â”€ Health Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/api/health", tags=["System"])
def health_check():
    """System health probe."""
    return {
        "status":   "healthy",
        "project":  settings.PROJECT_NAME,
        "version":  "2.0.0",
        "database": "sqlite",
        "modules":  [
            "auth", "logs", "threats", "score",
            "dashboard", "devices", "reports"
        ]
    }
