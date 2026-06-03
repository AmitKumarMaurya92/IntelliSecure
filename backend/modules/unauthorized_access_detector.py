"""
Unauthorized Access Detector
==============================
Identifies unauthorized file access attempts and blocked USB device events.

Detection Rules:
  - File access with status "Denied" → MEDIUM alert
  - USB device with action "Blocked" → HIGH alert
  - Multiple denied file accesses (≥3) by same user → HIGH alert (escalated)

Author: InteliSecure Team
"""

import datetime
from sqlalchemy.orm import Session
from collections import defaultdict

from ..models import FileAccessLog, USBLog
from .alert_manager import create_alert


def detect_unauthorized_file_access(db: Session) -> list[dict]:
    """
    Scan file_access_logs for 'Denied' status events.
    Escalates to High severity when same user has 3+ denials.
    """
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    denied_logs = (
        db.query(FileAccessLog)
        .filter(FileAccessLog.status == "Denied")
        .filter(FileAccessLog.timestamp >= since)
        .all()
    )

    # Group denied accesses by username
    user_denials: dict[str, list] = defaultdict(list)
    for log in denied_logs:
        user_denials[log.username].append(log.file_path)

    detected = []

    for username, file_paths in user_denials.items():
        count    = len(file_paths)
        severity = "High" if count >= 3 else "Medium"

        detected.append({
            "username":    username,
            "denied_count": count,
            "severity":    severity,
            "file_paths":  file_paths[:5]  # Show top 5 paths
        })

        create_alert(
            db=db,
            threat_type="Unauthorized File Access",
            severity=severity,
            source=username,
            description=(
                f"User '{username}' was denied access to {count} file(s) in the last hour. "
                f"Files attempted: {', '.join(file_paths[:3])}{'...' if count > 3 else ''}. "
                f"{'Multiple denials suggest possible insider threat or privilege escalation attempt.' if count >= 3 else 'Unauthorized access attempt detected.'}"
            )
        )

    return detected


def detect_blocked_usb_devices(db: Session) -> list[dict]:
    """
    Scan usb_logs for 'Blocked' action events indicating policy violations.
    """
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    blocked_usb = (
        db.query(USBLog)
        .filter(USBLog.action == "Blocked")
        .filter(USBLog.timestamp >= since)
        .all()
    )

    detected = []

    for log in blocked_usb:
        detected.append({
            "username":    log.username,
            "device_name": log.device_name,
            "device_id":   log.device_id,
        })

        create_alert(
            db=db,
            threat_type="Blocked USB Device",
            severity="High",
            source=log.username,
            description=(
                f"Unauthorized USB device blocked for user '{log.username}'. "
                f"Device: '{log.device_name}' (ID: {log.device_id}). "
                f"Possible data exfiltration attempt or policy violation."
            )
        )

    return detected


def detect_all_unauthorized(db: Session) -> dict:
    """
    Master function: run all unauthorized access detectors and return combined results.
    """
    file_incidents = detect_unauthorized_file_access(db)
    usb_incidents  = detect_blocked_usb_devices(db)

    return {
        "unauthorized_file_access": file_incidents,
        "blocked_usb_devices":      usb_incidents,
        "total_incidents":          len(file_incidents) + len(usb_incidents)
    }
