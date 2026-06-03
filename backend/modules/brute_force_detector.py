"""
Brute Force Attack Detector
============================
Scans the login_logs database table for repeated failed login attempts
from the same IP address within a short time window.

Detection Rule:
  â‰¥ 5 failed logins from same IP within 60 seconds â†’ CRITICAL alert

Author: IntelliSecure Team
"""

import datetime
from sqlalchemy.orm import Session
from collections import defaultdict

# Import models and alert manager using relative path
from ..models import LoginLog
from .alert_manager import create_alert


# Threshold configuration
FAILURE_THRESHOLD  = 5    # Minimum number of failures to trigger alert
TIME_WINDOW_SECS   = 60   # Window in seconds to count failures


def detect_brute_force(db: Session) -> list[dict]:
    """
    Scan recent login_logs for brute force patterns.

    Returns:
        List of dicts: { ip_address, failed_count, window_start, window_end }
        for each IP that exceeded the failure threshold.
    """
    # Pull all FAILED login attempts within the last 10 minutes for efficiency
    since = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

    failed_logs = (
        db.query(LoginLog)
        .filter(LoginLog.status == "Failed")
        .filter(LoginLog.timestamp >= since)
        .order_by(LoginLog.ip_address, LoginLog.timestamp)
        .all()
    )

    # Group failures by IP address
    ip_events: dict[str, list[datetime.datetime]] = defaultdict(list)
    for log in failed_logs:
        ts = log.timestamp
        # Handle both datetime objects and strings
        if isinstance(ts, str):
            ts = ts.replace("Z", "")
            try:
                ts = datetime.datetime.fromisoformat(ts)
            except Exception:
                ts = datetime.datetime.utcnow()
        ip_events[log.ip_address].append(ts)

    detected = []

    for ip, timestamps in ip_events.items():
        timestamps.sort()
        # Sliding window check
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end   = window_start + datetime.timedelta(seconds=TIME_WINDOW_SECS)
            # Count events within the window
            count = sum(1 for t in timestamps[i:] if t <= window_end)

            if count >= FAILURE_THRESHOLD:
                detected.append({
                    "ip_address":    ip,
                    "failed_count":  count,
                    "window_start":  window_start.isoformat(),
                    "window_end":    window_end.isoformat()
                })

                # Fire alert into the database (deduplication built into alert_manager)
                create_alert(
                    db=db,
                    threat_type="Brute Force Attack",
                    severity="Critical",
                    source=ip,
                    description=(
                        f"{count} failed login attempts detected from IP {ip} "
                        f"within {TIME_WINDOW_SECS} seconds. Possible credential "
                        f"stuffing or password spray attack."
                    )
                )
                break  # Avoid duplicate alerts per IP in same scan

    return detected
