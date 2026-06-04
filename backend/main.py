"""
IntelliSecure - Main FastAPI Application Entry Point
===================================================
AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System

Run with: uvicorn main:app --reload (from backend/ directory)
Or:       python -m uvicorn main:app --reload

Author: IntelliSecure Team
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# â”€â”€â”€ Core imports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from .config   import settings
from .database import engine, Base

# â”€â”€â”€ Model registration (must import before create_all) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from .models import (
    User, LoginLog, NetworkLog, FileAccessLog,
    MalwareLog, USBLog, Alert, ScanHistory,
    UserPreferences, UserSession
)

# â”€â”€â”€ Router imports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from .routes.auth_routes   import router as auth_router
from .routes.log_routes    import router as log_router
from .routes.threat_routes import router as threat_router
from .routes.score_routes  import router as score_router
from .routes.dashboard_routes import router as dashboard_router
from .routes.device_routes    import router as device_router
from backend.routes.report_routes    import router as report_router
from backend.routes.educational_routes import router as educational_router
from backend.routes.realtime_routes  import router as realtime_router
from backend.routes.risk_routes      import router as risk_router
from backend.routes.export_routes    import router as export_router
from backend.routes.user_routes      import router as user_router
from backend.routes.settings_routes  import router as settings_router

# â”€â”€â”€ DB Table Creation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Base.metadata.create_all(bind=engine)

# â”€â”€â”€ App Instantiation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System. "
        "Supports real-time threat monitoring, multi-source log correlation, "
        "explainable AI, automated reporting, and LAN device discovery."
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# â”€â”€â”€ CORS Middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# â”€â”€â”€ API Routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.include_router(auth_router,      prefix="/api/auth",      tags=["Authentication"])
app.include_router(log_router,       prefix="/api/logs",      tags=["Logs"])
app.include_router(threat_router,    prefix="/api/threats",   tags=["Threats"])
app.include_router(score_router,     prefix="/api/security-score", tags=["Security Score"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(device_router,    prefix="/api/devices",   tags=["LAN Devices"])
app.include_router(report_router,    prefix="/api/reports",   tags=["Reports"])
app.include_router(educational_router, prefix="/api/education", tags=["Education"])
app.include_router(realtime_router,     prefix="/api/realtime",   tags=["Real-Time Monitor"])
app.include_router(risk_router,      prefix="/api/risk",      tags=["Risk Analysis"])
app.include_router(export_router,    prefix="/api/export",    tags=["Export Data"])
app.include_router(user_router,      prefix="/api/users",     tags=["Users"])
app.include_router(settings_router,  prefix="/api/settings",  tags=["Settings"])

# â”€â”€â”€ Static File Serving â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR     = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

for sub in ["css", "js", "assets"]:
    os.makedirs(os.path.join(FRONTEND_DIR, sub), exist_ok=True)

app.mount("/css",    StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")),    name="css")
app.mount("/js",     StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")),     name="js")
app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

# â”€â”€â”€ Frontend Page Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/", include_in_schema=False)
@app.get("/login", include_in_schema=False)
@app.get("/login.html", include_in_schema=False)
def serve_login():
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))

@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/alerts", include_in_schema=False)
def serve_alerts():
    return FileResponse(os.path.join(FRONTEND_DIR, "alerts.html"))

@app.get("/devices", include_in_schema=False)
def serve_devices():
    return FileResponse(os.path.join(FRONTEND_DIR, "devices.html"))

@app.get("/reports", include_in_schema=False)
def serve_reports():
    return FileResponse(os.path.join(FRONTEND_DIR, "reports.html"))

# â”€â”€â”€ Health Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/api/health", tags=["System"])
def health_check():
    return {
        "status":   "healthy",
        "project":  settings.PROJECT_NAME,
        "version":  "2.0.0",
        "database": "sqlite",
        "modules":  ["auth", "logs", "threats", "score", "dashboard", "devices", "reports"]
    }
