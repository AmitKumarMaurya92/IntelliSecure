"""
Real-Time Threat Monitor (Orchestrator)
=========================================
Coordinates all threat detectors and runs them in a single scan operation.
Also integrates the ML anomaly detector if the model is available.

Usage:
    results = run_all_detectors(db)

Author: InteliSecure Team
"""

import datetime
from sqlalchemy.orm import Session

from .brute_force_detector         import detect_brute_force
from .port_scan_detector           import detect_port_scans
from .unauthorized_access_detector import detect_all_unauthorized


def run_all_detectors(db: Session) -> dict:
    """
    Execute all threat detectors sequentially and aggregate results.

    Returns:
        Dict containing:
          - scan_timestamp: ISO timestamp of when scan ran
          - brute_force:    list of detected brute force events
          - port_scans:     list of detected port scanning IPs
          - unauthorized:   dict of unauthorized file/USB events
          - ml_anomalies:   list of ML-detected anomalies (if model available)
          - total_threats:  total count of threats detected in this scan
          - summary:        human-readable summary text
    """
    scan_time = datetime.datetime.utcnow()
    results   = {"scan_timestamp": scan_time.isoformat() + "Z"}

    # ── 1. Brute Force Detection ──────────────────────────────────────────
    try:
        bf_events = detect_brute_force(db)
        results["brute_force"] = bf_events
    except Exception as e:
        results["brute_force"] = []
        results["brute_force_error"] = str(e)

    # ── 2. Port Scan Detection ────────────────────────────────────────────
    try:
        ps_events = detect_port_scans(db)
        results["port_scans"] = ps_events
    except Exception as e:
        results["port_scans"] = []
        results["port_scan_error"] = str(e)

    # ── 3. Unauthorized Access Detection ─────────────────────────────────
    try:
        ua_events = detect_all_unauthorized(db)
        results["unauthorized"] = ua_events
    except Exception as e:
        results["unauthorized"] = {"unauthorized_file_access": [], "blocked_usb_devices": [], "total_incidents": 0}
        results["unauthorized_error"] = str(e)

    # ── 4. ML Anomaly Detection ───────────────────────────────────────────
    # Attempt to load and run the ML predictor; gracefully skip if unavailable
    try:
        from ..ml.predict import detect_anomalies_from_logs
        ml_results = detect_anomalies_from_logs(db)
        results["ml_anomalies"] = ml_results
    except Exception:
        results["ml_anomalies"] = []  # Model not yet trained or unavailable

    # ── 5. Totals & Summary ───────────────────────────────────────────────
    bf_count  = len(results["brute_force"])
    ps_count  = len(results["port_scans"])
    ua_count  = results["unauthorized"].get("total_incidents", 0)
    ml_count  = len(results["ml_anomalies"])
    total     = bf_count + ps_count + ua_count + ml_count

    results["total_threats"]  = total
    results["scan_duration_ms"] = int(
        (datetime.datetime.utcnow() - scan_time).total_seconds() * 1000
    )
    results["summary"] = (
        f"Scan complete. Detected {bf_count} brute force event(s), "
        f"{ps_count} port scan(s), {ua_count} unauthorized access event(s), "
        f"{ml_count} ML anomal{'y' if ml_count == 1 else 'ies'}. "
        f"Total: {total} threat(s)."
    )

    return results
