from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from .config import settings
from .database import engine, Base

# Import models so they are registered before metadata create_all
from .models import User
from .api.auth_routes import router as auth_router

# Dynamic database creation on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Authentication Routes
app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])

# Resolve path to the frontend directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Ensure frontend folders exist
os.makedirs(os.path.join(FRONTEND_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(FRONTEND_DIR, "js"), exist_ok=True)
os.makedirs(os.path.join(FRONTEND_DIR, "assets"), exist_ok=True)

# Mount static asset folders
app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")
app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

# Page Routes (delivering HTML files from frontend)
@app.get("/")
@app.get("/login")
def get_login():
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))

@app.get("/dashboard")
def get_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

@app.get("/reports")
def get_reports():
    return FileResponse(os.path.join(FRONTEND_DIR, "reports.html"))

@app.get("/devices")
def get_devices():
    return FileResponse(os.path.join(FRONTEND_DIR, "devices.html"))

@app.get("/alerts")
def get_alerts():
    return FileResponse(os.path.join(FRONTEND_DIR, "alerts.html"))

# Base API Health Check Endpoint
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "database": "sqlite"
    }

