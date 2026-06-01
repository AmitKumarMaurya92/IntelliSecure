"""
Security Score Engine
======================
Calculates the current security health score (0–100) based on live data
from all threat logs and active alerts in the database.

Formula:
    score = 100
    score -= min(failed_logins   * 2,  30)   # login penalty     (max -30)
    score -= min(malware_count   * 5,  25)   # malware penalty   (max -25)
    score -= min(port_scan_ips   * 3,  20)   # port scan penalty (max -20)
    score -= min(denied_files    * 2,  15)   # file access penalty (max -15)
    score -= min(critical_alerts * 3,  10)   # active critical alerts (max -10)
    score  = max(0, score)

Risk Levels:
    80–100 → Low
    60–79  → Medium
    40–59  → High
    0–39   → Critical

Author: InteliSecure Team
"""

import datetime
from sqlalchemy.orm import Session

from ..models import LoginLog, MalwareLog, NetworkLog, FileAccessLog, Alert


def calculate_security_score(db: Session) -> dict:
    """
    Compute the current security score from live database data.

    Returns:
        Dict with: score, risk_level, breakdown, computed_at
    """
    since_24h  = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    since_1h   = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

    # ── Data Queries ──────────────────────────────────────────────────────────
    failed_logins = (
        db.query(LoginLog)
        .filter(LoginLog.status == "Failed")
        .filter(LoginLog.timestamp >= since_24h)
        .count()
    )

    malware_count = (
        db.query(MalwareLog)
        .filter(MalwareLog.timestamp >= since_24h)
        .count()
    )

    # Count distinct IPs that touched many ports (crude port scan count)
    from sqlalchemy import func, distinct
    port_scan_sources = (
        db.query(NetworkLog.source_ip)
        .filter(NetworkLog.timestamp >= since_1h)
        .group_by(NetworkLog.source_ip)
        .having(func.count(distinct(NetworkLog.port)) >= 10)
        .count()
    )

    denied_files = (
        db.query(FileAccessLog)
        .filter(FileAccessLog.status == "Denied")
        .filter(FileAccessLog.timestamp >= since_24h)
        .count()
    )

    active_critical_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "Critical")
        .filter(Alert.resolved == False)
        .count()
    )

    active_high_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "High")
        .filter(Alert.resolved == False)
        .count()
    )

    # ── Score Calculation ─────────────────────────────────────────────────────
    login_penalty    = min(failed_logins    * 2, 30)
    malware_penalty  = min(malware_count    * 5, 25)
    portscan_penalty = min(port_scan_sources * 3, 20)
    filaccess_penalty = min(denied_files    * 2, 15)
    alert_penalty    = min(active_critical_alerts * 3 + active_high_alerts, 10)

    total_penalty = (
        login_penalty + malware_penalty + portscan_penalty +
        filaccess_penalty + alert_penalty
    )
    score = max(0, 100 - total_penalty)

    # ── Risk Level ────────────────────────────────────────────────────────────
    if score >= 80:
        risk_level = "Low"
        risk_color = "#10b981"   # green
    elif score >= 60:
        risk_level = "Medium"
        risk_color = "#f59e0b"   # amber
    elif score >= 40:
        risk_level = "High"
        risk_color = "#ef4444"   # red
    else:
        risk_level = "Critical"
        risk_color = "#7c3aed"   # purple

    # ── Trend (last 7 days) — computed from daily penalties ──────────────────
    trend = _compute_score_trend(db)

    return {
        "score":        score,
        "risk_level":   risk_level,
        "risk_color":   risk_color,
        "total_penalty": total_penalty,
        "breakdown": {
            "failed_logins":        {"value": failed_logins,      "penalty": login_penalty,     "max_penalty": 30},
            "malware_detected":     {"value": malware_count,       "penalty": malware_penalty,   "max_penalty": 25},
            "port_scan_sources":    {"value": port_scan_sources,   "penalty": portscan_penalty,  "max_penalty": 20},
            "unauthorized_accesses":{"value": denied_files,        "penalty": filaccess_penalty, "max_penalty": 15},
            "active_critical_alerts":{"value": active_critical_alerts, "penalty": alert_penalty, "max_penalty": 10}
        },
        "trend":        trend,
        "computed_at":  datetime.datetime.utcnow().isoformat() + "Z"
    }


def _compute_score_trend(db: Session) -> list[dict]:
    """
    Approximate security score for each of the last 7 days.
    Uses daily failed login counts as the primary signal.
    """
    trend = []
    for days_ago in range(6, -1, -1):
        day_start = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago + 1)
        day_end   = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)

        daily_failures = (
            db.query(LoginLog)
            .filter(LoginLog.status == "Failed")
            .filter(LoginLog.timestamp >= day_start)
            .filter(LoginLog.timestamp < day_end)
            .count()
        )
        daily_malware = (
            db.query(MalwareLog)
            .filter(MalwareLog.timestamp >= day_start)
            .filter(MalwareLog.timestamp < day_end)
            .count()
        )
        daily_denied = (
            db.query(FileAccessLog)
            .filter(FileAccessLog.status == "Denied")
            .filter(FileAccessLog.timestamp >= day_start)
            .filter(FileAccessLog.timestamp < day_end)
            .count()
        )

        day_penalty = (
            min(daily_failures * 2, 30) +
            min(daily_malware  * 5, 25) +
            min(daily_denied   * 2, 15)
        )
        day_score = max(0, 100 - day_penalty)

        trend.append({
            "date":  day_end.strftime("%b %d"),
            "score": day_score
        })

    return trend


def get_risk_level(score: int) -> str:
    """Helper: convert a numeric score to a risk label."""
    if score >= 80: return "Low"
    if score >= 60: return "Medium"
    if score >= 40: return "High"
    return "Critical"
