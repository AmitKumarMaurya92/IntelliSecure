"""
LAN Device Monitor API Routes
================================
REST endpoints for LAN device discovery, inventory, and unknown device detection.

Endpoints:
  GET  /api/devices/         — Return last cached device inventory
  POST /api/devices/scan     — Trigger a fresh LAN scan (Admin/Analyst only)
  GET  /api/devices/unknown  — Return only unknown/unregistered devices

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
import datetime

from ..database import get_db
from ..auth     import get_current_user, RoleChecker
from ..modules.lan_scanner import discover_devices

router = APIRouter()

# Role dependencies
analyst_or_admin  = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))
all_authenticated = Depends(get_current_user)

# ─── In-memory cache for last scan result ─────────────────────────────────────
# In production this would be stored in DB or Redis
_last_scan_result: dict = {}
_last_scan_time: str    = ""


@router.get("/", summary="Device inventory")
def get_device_inventory(
    _: object = all_authenticated
):
    """
    Return the device inventory from the last LAN scan.
    If no scan has been performed, returns an empty inventory.
    """
    if not _last_scan_result:
        return {
            "message":      "No scan performed yet. Use POST /api/devices/scan to start.",
            "devices":      [],
            "total_online": 0,
            "last_scan":    None
        }

    return {**_last_scan_result, "last_scan": _last_scan_time}


@router.post("/scan", summary="Trigger LAN scan")
def trigger_lan_scan(
    subnet: str     = "192.168.1.0/24",
    db:     Session = Depends(get_db),
    _:      object  = analyst_or_admin
):
    """
    Perform a live LAN scan of the specified subnet.
    WARNING: This may take 30–60 seconds for a /24 subnet.
    Requires Analyst or Admin role.
    """
    global _last_scan_result, _last_scan_time

    try:
        result            = discover_devices(db=db, subnet=subnet)
        _last_scan_result = result
        _last_scan_time   = datetime.datetime.utcnow().isoformat() + "Z"
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"LAN scan failed: {str(e)}"
        )


@router.get("/unknown", summary="Unknown devices")
def get_unknown_devices(
    _: object = analyst_or_admin
):
    """Return only devices that are not recognized in network_logs (unknown devices)."""
    if not _last_scan_result:
        return {
            "message":       "No scan performed yet. Use POST /api/devices/scan first.",
            "unknown_devices": [],
            "count":          0
        }

    unknown = [d for d in _last_scan_result.get("devices", []) if not d.get("is_known", True)]

    return {
        "unknown_devices": unknown,
        "count":           len(unknown),
        "last_scan":       _last_scan_time
    }
