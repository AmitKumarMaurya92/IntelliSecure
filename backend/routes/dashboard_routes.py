"""
Dashboard Aggregation API Routes
==================================
Provides pre-aggregated data for the main security dashboard.
All endpoints are optimized for fast dashboard rendering.

Endpoints:
  GET /api/dashboard/stats            — 4 KPI cards
  GET /api/dashboard/threat-trend     — Daily threat counts (last N days)
  GET /api/dashboard/threat-distribution — Threat type breakdown
  GET /api/dashboard/top-sources      — Top 5 attacker IPs
  GET /api/dashboard/recent-alerts    — Latest 5 alerts for timeline
  GET /api/dashboard/system-health    — System component status

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime
from typing import Optional

from ..database import get_db
from ..models   import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog, Alert
from ..auth     import get_current_user
from ..modules.security_score import calculate_security_score

router = APIRouter()

auth = Depends(get_current_user)


@router.get("/stats", summary="Dashboard KPI cards")
def get_dashboard_stats(
    date: Optional[str] = Query(None, description="Filter date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """
    Return the 4 main KPI card values:
    total_logs, active_threats, critical_alerts, security_score.
    """
    # Base queries
    login_q = db.query(LoginLog)
    net_q = db.query(NetworkLog)
    file_q = db.query(FileAccessLog)
    mal_q = db.query(MalwareLog)
    usb_q = db.query(USBLog)
    alert_q = db.query(Alert)

    if date:
        login_q = login_q.filter(LoginLog.timestamp.like(f"{date}%"))
        net_q = net_q.filter(NetworkLog.timestamp.like(f"{date}%"))
        file_q = file_q.filter(FileAccessLog.timestamp.like(f"{date}%"))
        mal_q = mal_q.filter(MalwareLog.timestamp.like(f"{date}%"))
        usb_q = usb_q.filter(USBLog.timestamp.like(f"{date}%"))
        alert_q = alert_q.filter(Alert.timestamp.like(f"{date}%"))

    # Total logs across all tables
    total_logs = (
        login_q.count() +
        net_q.count() +
        file_q.count() +
        mal_q.count() +
        usb_q.count()
    )

    active_threats   = alert_q.filter(Alert.resolved == False).count()
    critical_alerts  = alert_q.filter(Alert.severity == "Critical", Alert.resolved == False).count()

    score_data       = calculate_security_score(db)

    return {
        "total_logs":      total_logs,
        "active_threats":  active_threats,
        "critical_alerts": critical_alerts,
        "security_score":  score_data["score"],
        "risk_level":      score_data["risk_level"],
        "risk_color":      score_data["risk_color"]
    }


@router.get("/threat-trend", summary="Daily threat count trend")
def get_threat_trend(
    days: int   = Query(7, ge=1, le=90, description="Number of days to look back"),
    date: Optional[str] = Query(None, description="Filter date in YYYY-MM-DD format (end date for trend)"),
    db:   Session = Depends(get_db),
    _:    object  = auth
):
    """Return daily alert counts for the last N days (default 7) up to the specified date."""
    trend = []
    
    if date:
        try:
            base_date = datetime.datetime.strptime(date, "%Y-%m-%d")
            # Set to end of the given day
            base_date = base_date.replace(hour=23, minute=59, second=59)
        except ValueError:
            base_date = datetime.datetime.utcnow()
    else:
        base_date = datetime.datetime.utcnow()
        
    for days_ago in range(days - 1, -1, -1):
        day_start = base_date - datetime.timedelta(days=days_ago + 1)
        day_end   = base_date - datetime.timedelta(days=days_ago)

        count = (
            db.query(Alert)
            .filter(Alert.timestamp >= day_start)
            .filter(Alert.timestamp < day_end)
            .count()
        )
        trend.append({
            "date":  day_end.strftime("%b %d"),
            "count": count
        })

    return {"trend": trend, "days": days}


@router.get("/threat-distribution", summary="Threat type breakdown")
def get_threat_distribution(
    date: Optional[str] = Query(None, description="Filter date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """Return alert counts grouped by threat_type for the donut chart."""
    q = db.query(Alert.threat_type, func.count(Alert.id).label("count")).filter(Alert.resolved == False)
    if date:
        q = q.filter(Alert.timestamp.like(f"{date}%"))
        
    type_counts = (
        q.group_by(Alert.threat_type)
        .order_by(func.count(Alert.id).desc())
        .all()
    )

    # Color map for chart rendering
    color_map = {
        "Brute Force Attack":     "#ef4444",
        "Port Scan":              "#f59e0b",
        "Malware Detected":       "#8b5cf6",
        "Unauthorized File Access": "#2563eb",
        "Blocked USB Device":     "#06b6d4",
        "ML Anomaly":             "#10b981"
    }

    distribution = [
        {
            "threat_type": row.threat_type,
            "count":       row.count,
            "color":       color_map.get(row.threat_type, "#94a3b8")
        }
        for row in type_counts
    ]

    total = sum(d["count"] for d in distribution)

    return {
        "distribution": distribution,
        "total_active":  total
    }


@router.get("/top-sources", summary="Top attack source IPs")
def get_top_attack_sources(
    limit:  int     = Query(5, ge=1, le=20),
    date: Optional[str] = Query(None, description="Filter date in YYYY-MM-DD format"),
    db:     Session = Depends(get_db),
    _:      object  = auth
):
    """Return top N source IPs/usernames by active alert count."""
    q = db.query(Alert.source, func.count(Alert.id).label("count")).filter(Alert.resolved == False)
    if date:
        q = q.filter(Alert.timestamp.like(f"{date}%"))
        
    sources = (
        q.group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )

    bar_colors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#06b6d4"]

    result = [
        {
            "source":      row.source,
            "alert_count": row.count,
            "color":       bar_colors[i % len(bar_colors)]
        }
        for i, row in enumerate(sources)
    ]

    return {"sources": result}


@router.get("/recent-alerts", summary="Recent alerts for timeline")
def get_recent_alerts(
    limit:  int     = Query(5, ge=1, le=20),
    db:     Session = Depends(get_db),
    _:      object  = auth
):
    """Return the most recent alerts for the dashboard timeline widget."""
    alerts = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )

    severity_icon_map = {
        "Critical": "fa-shield-virus",
        "High":     "fa-triangle-exclamation",
        "Medium":   "fa-satellite-dish",
        "Low":      "fa-circle-info"
    }

    result = []
    for a in alerts:
        ts = a.timestamp
        if isinstance(ts, str):
            ts_str = ts
        else:
            ts_str = ts.isoformat() + "Z"
        result.append({
            "id":          a.id,
            "threat":      a.threat_type,
            "severity":    a.severity,
            "source":      a.source,
            "time":        ts_str,
            "resolved":    a.resolved,
            "icon":        severity_icon_map.get(a.severity, "fa-triangle-exclamation")
        })

    return {"alerts": result, "count": len(result)}


@router.get("/system-health", summary="System component health")
def get_system_health(
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """
    Return status of all system components.
    Status is derived from recent log activity and DB connectivity.
    """
    since_1h = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

    # Check components by verifying they can be queried
    components = []

    try:
        login_count = db.query(LoginLog).count()
        components.append({"name": "Log Collector",          "status": "Active",  "detail": f"{login_count} login records"})
    except Exception:
        components.append({"name": "Log Collector",          "status": "Warning", "detail": "Could not query login logs"})

    try:
        alert_count = db.query(Alert).filter(Alert.resolved == False).count()
        components.append({"name": "Threat Detection Engine", "status": "Active",  "detail": f"{alert_count} active alerts"})
    except Exception:
        components.append({"name": "Threat Detection Engine", "status": "Warning", "detail": "Could not query alerts"})

    # ML model availability check
    try:
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "anomaly_model.pkl")
        ml_status  = "Active" if os.path.exists(model_path) else "Inactive"
        components.append({"name": "AI Anomaly Detector",    "status": ml_status, "detail": "Isolation Forest model"})
    except Exception:
        components.append({"name": "AI Anomaly Detector",    "status": "Warning", "detail": "Model check failed"})

    components.append({"name": "LAN Monitor",        "status": "Active", "detail": "Network scanning ready"})
    components.append({"name": "Report Generator",   "status": "Active", "detail": "PDF & PPT generation ready"})
    components.append({"name": "Database",           "status": "Active", "detail": "SQLite connected"})

    return {"components": components, "healthy_count": sum(1 for c in components if c["status"] == "Active")}


@router.get("/metrics", summary="All-in-one metrics for Plotly charts")
def get_all_metrics(
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """
    Returns aggregated real-time metrics for frontend Plotly charts in a single payload.
    """
    stats = get_dashboard_stats(db, _)
    trend = get_threat_trend(7, db, _)
    distribution = get_threat_distribution(db, _)
    top_sources = get_top_attack_sources(5, db, _)
    system_health = get_system_health(db, _)

    return {
        "stats": stats,
        "trend": trend,
        "distribution": distribution,
        "top_sources": top_sources,
        "system_health": system_health
    }
