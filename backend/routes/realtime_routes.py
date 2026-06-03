"""
Real-Time Monitor API Routes
===============================
REST endpoints for the live security monitoring dashboard.

Endpoints:
  POST /api/realtime/scan      — Trigger full detector scan and persist results
  GET  /api/realtime/status    — Detector module health and scan readiness
  GET  /api/realtime/history   — Last N scan summaries for timeline chart

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime, os

from ..database import get_db
from ..models   import (
    Alert, LoginLog, NetworkLog, FileAccessLog,
    MalwareLog, USBLog, ScanHistory
)
from ..auth     import get_current_user, RoleChecker
from ..modules.realtime_monitor import run_all_detectors

router = APIRouter()

# Role dependencies
analyst_or_admin = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))
all_authenticated = Depends(get_current_user)


# ─── POST /scan — Run all detectors and persist results ───────────────────────

@router.post("/scan", summary="Run real-time threat scan")
def run_realtime_scan(
    db: Session = Depends(get_db),
    _: object   = analyst_or_admin
):
    """
    Trigger a full real-time threat detection scan.
    Runs brute force, port scan, unauthorized access, and ML anomaly detectors.
    Persists a ScanHistory record and returns the full result payload.
    """
    try:
        results = run_all_detectors(db)
    except Exception as e:
        # If any detector crashes, return a partial result instead of 500
        results = {
            "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "brute_force": [],
            "port_scans": [],
            "unauthorized": {"unauthorized_file_access": [], "blocked_usb_devices": [], "total_incidents": 0},
            "ml_anomalies": [],
            "total_threats": 0,
            "scan_duration_ms": 0,
            "summary": f"Scan encountered an error: {str(e)}"
        }

    # Persist scan history record
    bf_count = len(results.get("brute_force", []))
    ps_count = len(results.get("port_scans", []))
    ua_data  = results.get("unauthorized", {})
    ua_count = ua_data.get("total_incidents", 0) if isinstance(ua_data, dict) else 0
    ml_count = len(results.get("ml_anomalies", []))

    try:
        scan_record = ScanHistory(
            brute_force_count  = bf_count,
            port_scan_count    = ps_count,
            unauthorized_count = ua_count,
            ml_anomaly_count   = ml_count,
            total_threats      = results.get("total_threats", 0),
            scan_duration_ms   = results.get("scan_duration_ms", 0),
            summary            = results.get("summary", "")
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        scan_id = scan_record.id
    except Exception:
        db.rollback()
        scan_id = None

    # Build the flat events list for the live feed
    try:
        events = _build_events_list(results)
    except Exception:
        events = []

    return {
        "scan_id":          scan_id,
        "scan_timestamp":   results.get("scan_timestamp"),
        "brute_force_count": bf_count,
        "port_scan_count":   ps_count,
        "unauthorized_count": ua_count,
        "ml_anomaly_count":  ml_count,
        "total_threats":     results.get("total_threats", 0),
        "scan_duration_ms":  results.get("scan_duration_ms", 0),
        "summary":           results.get("summary", ""),
        "events":            events,
        "raw": {
            "brute_force":  results.get("brute_force", []),
            "port_scans":   results.get("port_scans", []),
            "unauthorized": results.get("unauthorized", {}),
            "ml_anomalies": results.get("ml_anomalies", [])
        }
    }


# ─── GET /status — Detector health and scan readiness ─────────────────────────

@router.get("/status", summary="Detector module status")
def get_realtime_status(
    db: Session = Depends(get_db),
    _: object   = all_authenticated
):
    """
    Return health status of each detection module and overall scan readiness.
    """
    detectors = []

    # Brute Force Detector
    try:
        from ..modules.brute_force_detector import detect_brute_force
        detectors.append({
            "name": "Brute Force Detector",
            "icon": "fa-lock",
            "status": "active",
            "description": "Monitors login attempts for credential stuffing patterns"
        })
    except Exception:
        detectors.append({
            "name": "Brute Force Detector",
            "icon": "fa-lock",
            "status": "error",
            "description": "Module failed to load"
        })

    # Port Scan Detector
    try:
        from ..modules.port_scan_detector import detect_port_scans
        detectors.append({
            "name": "Port Scan Detector",
            "icon": "fa-network-wired",
            "status": "active",
            "description": "Detects network reconnaissance and port sweeping"
        })
    except Exception:
        detectors.append({
            "name": "Port Scan Detector",
            "icon": "fa-network-wired",
            "status": "error",
            "description": "Module failed to load"
        })

    # Unauthorized Access Detector
    try:
        from ..modules.unauthorized_access_detector import detect_all_unauthorized
        detectors.append({
            "name": "Unauthorized Access Detector",
            "icon": "fa-folder-open",
            "status": "active",
            "description": "Tracks unauthorized file and USB device access"
        })
    except Exception:
        detectors.append({
            "name": "Unauthorized Access Detector",
            "icon": "fa-folder-open",
            "status": "error",
            "description": "Module failed to load"
        })

    # ML Anomaly Detector
    try:
        ml_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "ml"
        )
        model_path = os.path.join(ml_dir, "anomaly_model.pkl")
        ml_available = os.path.exists(model_path)
        detectors.append({
            "name": "ML Anomaly Detector",
            "icon": "fa-brain",
            "status": "active" if ml_available else "inactive",
            "description": "Isolation Forest anomaly detection" if ml_available else "Model not trained yet"
        })
    except Exception:
        detectors.append({
            "name": "ML Anomaly Detector",
            "icon": "fa-brain",
            "status": "error",
            "description": "Model check failed"
        })

    # Last scan info
    last_scan = db.query(ScanHistory).order_by(ScanHistory.id.desc()).first()
    last_scan_info = None
    if last_scan:
        last_scan_info = {
            "id": last_scan.id,
            "timestamp": last_scan.timestamp,
            "total_threats": last_scan.total_threats,
            "duration_ms": last_scan.scan_duration_ms
        }

    active_count = sum(1 for d in detectors if d["status"] == "active")

    return {
        "scan_ready":    active_count > 0,
        "detectors":     detectors,
        "active_count":  active_count,
        "total_count":   len(detectors),
        "last_scan":     last_scan_info
    }


# ─── GET /history — Last N scan summaries ─────────────────────────────────────

@router.get("/history", summary="Scan history for timeline chart")
def get_scan_history(
    limit: int  = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: object   = all_authenticated
):
    """Return the most recent scan summaries for the timeline chart."""
    scans = (
        db.query(ScanHistory)
        .order_by(ScanHistory.id.desc())
        .limit(limit)
        .all()
    )

    # Reverse so oldest is first (for chart x-axis)
    scans.reverse()

    history = []
    for s in scans:
        history.append({
            "id":                s.id,
            "timestamp":         s.timestamp,
            "brute_force_count": s.brute_force_count,
            "port_scan_count":   s.port_scan_count,
            "unauthorized_count": s.unauthorized_count,
            "ml_anomaly_count":  s.ml_anomaly_count,
            "total_threats":     s.total_threats,
            "scan_duration_ms":  s.scan_duration_ms,
            "summary":           s.summary
        })

    return {"history": history, "count": len(history)}


# ─── Helper: Build flat events list from scan results ─────────────────────────

def _build_events_list(results: dict) -> list:
    """
    Flatten the detector outputs into a unified event list for the live feed.
    Each event has: type, severity, source, description, icon, color.
    """
    events = []

    # Brute force events
    # Detector returns: { ip_address, failed_count, window_start, window_end }
    for bf in results.get("brute_force", []):
        ip = bf.get("ip_address", bf.get("ip", bf.get("source_ip", "Unknown")))
        count = bf.get("failed_count", bf.get("failed_attempts", bf.get("count", 0)))
        events.append({
            "type":        "Brute Force",
            "severity":    "Critical" if count >= 10 else "High",
            "source":      ip,
            "description": f"{count} failed login attempts detected from {ip}",
            "icon":        "fa-lock",
            "color":       "#ef4444"
        })

    # Port scan events
    # Detector returns: { source_ip, distinct_ports (int), ports_scanned (list), window_start }
    for ps in results.get("port_scans", []):
        ip = ps.get("source_ip", ps.get("ip", "Unknown"))
        port_count = ps.get("distinct_ports", 0)
        # ports_scanned is a list of port numbers; use distinct_ports for the count
        if port_count == 0:
            scanned = ps.get("ports_scanned", [])
            port_count = len(scanned) if isinstance(scanned, list) else scanned
        events.append({
            "type":        "Port Scan",
            "severity":    "High" if port_count >= 20 else "Medium",
            "source":      ip,
            "description": f"Port scanning detected — {port_count} unique ports from {ip}",
            "icon":        "fa-network-wired",
            "color":       "#f59e0b"
        })

    # Unauthorized access events
    # File detector returns: { username, denied_count, severity, file_paths (list) }
    # USB detector returns:  { username, device_name, device_id }
    ua_data = results.get("unauthorized", {})
    if isinstance(ua_data, dict):
        for fa in ua_data.get("unauthorized_file_access", []):
            user = fa.get("username", "Unknown")
            file_paths = fa.get("file_paths", [])
            path = file_paths[0] if isinstance(file_paths, list) and file_paths else fa.get("file_path", "Unknown")
            denied_count = fa.get("denied_count", len(file_paths) if isinstance(file_paths, list) else 1)
            events.append({
                "type":        "Unauthorized File Access",
                "severity":    fa.get("severity", "High"),
                "source":      user,
                "description": f"Denied file access by {user} ({denied_count} file(s)): {path}",
                "icon":        "fa-folder-open",
                "color":       "#2563eb"
            })
        for usb in ua_data.get("blocked_usb_devices", []):
            user = usb.get("username", "Unknown")
            device = usb.get("device_name", "Unknown device")
            events.append({
                "type":        "Blocked USB Device",
                "severity":    "High",
                "source":      user,
                "description": f"USB device blocked: {device} by {user}",
                "icon":        "fa-usb",
                "color":       "#06b6d4"
            })

    # ML anomalies
    for ml in results.get("ml_anomalies", []):
        source = ml.get("source", ml.get("ip", "Unknown"))
        events.append({
            "type":        "ML Anomaly",
            "severity":    "Medium",
            "source":      str(source),
            "description": f"AI-detected anomalous behaviour from {source}",
            "icon":        "fa-brain",
            "color":       "#10b981"
        })

    return events

