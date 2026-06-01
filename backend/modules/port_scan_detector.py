"""
Port Scan Detector
==================
Analyzes network_logs to identify IP addresses performing port scans.

Detection Rule:
  ≥ 10 distinct destination ports from same source IP within 30 seconds → HIGH alert

Author: InteliSecure Team
"""

import datetime
from sqlalchemy.orm import Session
from collections import defaultdict

from ..models import NetworkLog
from .alert_manager import create_alert


# Threshold configuration
PORT_THRESHOLD   = 10   # Minimum distinct ports to trigger
TIME_WINDOW_SECS = 30   # Window in seconds


def detect_port_scans(db: Session) -> list[dict]:
    """
    Scan recent network_logs for port scanning patterns.

    Returns:
        List of dicts: { source_ip, distinct_ports, ports_scanned, window_start }
        for each detected port scanner.
    """
    since = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)

    recent_logs = (
        db.query(NetworkLog)
        .filter(NetworkLog.timestamp >= since)
        .order_by(NetworkLog.source_ip, NetworkLog.timestamp)
        .all()
    )

    # Group by source_ip: list of (timestamp, port) tuples
    ip_events: dict[str, list[tuple]] = defaultdict(list)
    for log in recent_logs:
        ts = log.timestamp
        if isinstance(ts, str):
            ts = ts.replace("Z", "")
            try:
                ts = datetime.datetime.fromisoformat(ts)
            except Exception:
                ts = datetime.datetime.utcnow()
        ip_events[log.source_ip].append((ts, log.port))

    detected = []

    for source_ip, events in ip_events.items():
        events.sort(key=lambda x: x[0])

        for i in range(len(events)):
            window_start = events[i][0]
            window_end   = window_start + datetime.timedelta(seconds=TIME_WINDOW_SECS)

            # Collect distinct ports within the window
            ports_in_window = set(
                port for ts, port in events[i:]
                if ts <= window_end
            )

            if len(ports_in_window) >= PORT_THRESHOLD:
                detected.append({
                    "source_ip":      source_ip,
                    "distinct_ports": len(ports_in_window),
                    "ports_scanned":  sorted(list(ports_in_window)),
                    "window_start":   window_start.isoformat()
                })

                create_alert(
                    db=db,
                    threat_type="Port Scan",
                    severity="High",
                    source=source_ip,
                    description=(
                        f"IP {source_ip} contacted {len(ports_in_window)} distinct ports "
                        f"within {TIME_WINDOW_SECS} seconds. "
                        f"Ports: {sorted(list(ports_in_window))[:10]}... "
                        f"Possible reconnaissance or vulnerability scanning."
                    )
                )
                break  # One alert per IP per scan

    return detected
