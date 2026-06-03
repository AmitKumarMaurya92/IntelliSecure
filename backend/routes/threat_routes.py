"""
Threat Detection API Routes
=============================
REST endpoints for listing, scanning, explaining, and resolving security threats.

Endpoints:
  GET  /api/threats/           — List all alerts (paginated)
  GET  /api/threats/active     — Unresolved alerts only
  GET  /api/threats/stats      — Threat count statistics
  GET  /api/threats/top-sources — Top attacker IPs
  POST /api/threats/scan       — Trigger real-time detector scan
  GET  /api/threats/{id}       — Get single alert
  GET  /api/threats/{id}/explain — XAI explanation for an alert
  GET  /api/threats/{id}/recommendations — Mitigation recommendations
  POST /api/threats/{id}/resolve — Resolve an alert

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
import datetime

from ..database import get_db
from ..models   import Alert, LoginLog
from ..auth     import get_current_user, RoleChecker
from ..modules.realtime_monitor       import run_all_detectors
from ..modules.threat_explainer       import explain_threat
from ..modules.recommendation_engine import get_recommendations_for_threat

router = APIRouter()

# Role dependencies
analyst_or_admin = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))
all_authenticated = Depends(get_current_user)


# ─── Helper: Alert → Dict ─────────────────────────────────────────────────────

def alert_to_dict(alert: Alert) -> dict:
    """Serialize an Alert ORM object to a response dictionary."""
    ts = alert.timestamp
    if isinstance(ts, str):
        ts_str = ts
    else:
        ts_str = ts.isoformat() + "Z"
    return {
        "id":               alert.id,
        "timestamp":        ts_str,
        "threat_type":      alert.threat_type,
        "severity":         alert.severity,
        "source":           alert.source,
        "description":      alert.description,
        "resolved":         alert.resolved,
        "resolution_notes": alert.resolution_notes
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/", summary="List all alerts")
def list_alerts(
    limit:    int           = Query(50, ge=1, le=500),
    offset:   int           = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="Filter by severity: Low, Medium, High, Critical"),
    resolved: Optional[bool]= Query(None, description="Filter by resolved status"),
    db:       Session       = Depends(get_db),
    _:        object        = all_authenticated
):
    """List all security alerts with optional severity and resolved filters."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if resolved is not None:
        query = query.filter(Alert.resolved == resolved)

    total   = query.count()
    alerts  = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "alerts":  [alert_to_dict(a) for a in alerts]
    }


@router.get("/active", summary="List unresolved active threats")
def get_active_threats(
    limit: int = Query(50, ge=1, le=200),
    date: Optional[str] = Query(None, description="Filter date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    _: object = all_authenticated
):
    """Return all unresolved alerts (active threats)."""
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    q = db.query(Alert).filter(Alert.resolved == False)
    if date:
        q = q.filter(Alert.timestamp.like(f"{date}%"))
        
    alerts = (
        q.order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.severity, 99))

    return {
        "count":  len(sorted_alerts),
        "alerts": [alert_to_dict(a) for a in sorted_alerts]
    }


@router.get("/stats", summary="Alert statistics")
def get_alert_stats(
    db: Session = Depends(get_db),
    _: object   = all_authenticated
):
    """Return aggregated alert counts by severity and resolution status."""
    total        = db.query(Alert).count()
    active       = db.query(Alert).filter(Alert.resolved == False).count()
    resolved     = db.query(Alert).filter(Alert.resolved == True).count()
    critical     = db.query(Alert).filter(Alert.severity == "Critical", Alert.resolved == False).count()
    high         = db.query(Alert).filter(Alert.severity == "High",     Alert.resolved == False).count()
    medium       = db.query(Alert).filter(Alert.severity == "Medium",   Alert.resolved == False).count()
    low          = db.query(Alert).filter(Alert.severity == "Low",      Alert.resolved == False).count()

    # By threat type
    type_counts = (
        db.query(Alert.threat_type, func.count(Alert.id).label("count"))
        .filter(Alert.resolved == False)
        .group_by(Alert.threat_type)
        .all()
    )

    return {
        "total":    total,
        "active":   active,
        "resolved": resolved,
        "by_severity": {
            "Critical": critical,
            "High":     high,
            "Medium":   medium,
            "Low":      low
        },
        "by_type": {row.threat_type: row.count for row in type_counts}
    }


@router.get("/top-sources", summary="Top attacker IPs")
def get_top_sources(
    limit:  int     = Query(10, ge=1, le=50),
    db:     Session = Depends(get_db),
    _:      object  = all_authenticated
):
    """Return the top IP addresses/usernames by alert count."""
    top_sources = (
        db.query(Alert.source, func.count(Alert.id).label("count"))
        .filter(Alert.resolved == False)
        .group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )

    return {
        "sources": [
            {"source": row.source, "alert_count": row.count}
            for row in top_sources
        ]
    }


@router.post("/scan", summary="Run real-time threat scan")
def run_threat_scan(
    db: Session = Depends(get_db),
    _: object   = analyst_or_admin
):
    """
    Trigger a full real-time threat detection scan.
    Runs all detectors: brute force, port scan, unauthorized access, and ML anomaly.
    Requires Analyst or Admin role.
    """
    results = run_all_detectors(db)
    return results


@router.get("/{alert_id}", summary="Get single alert")
def get_alert(
    alert_id: int,
    db:       Session = Depends(get_db),
    _:        object  = all_authenticated
):
    """Retrieve a specific alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return alert_to_dict(alert)


@router.get("/{alert_id}/explain", summary="XAI explanation for an alert")
def explain_alert(
    alert_id: int,
    db:       Session = Depends(get_db),
    _:        object  = all_authenticated
):
    """
    Return an Explainable AI (XAI) explanation for a specific alert.
    Provides threat_name, severity, technical_reason, impact, and recommendations.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    context = {
        "source":      alert.source,
        "severity":    alert.severity,
        "timestamp":   str(alert.timestamp),
        "description": alert.description
    }

    explanation = explain_threat(alert.threat_type, context)
    return {
        "alert_id":    alert_id,
        "alert":       alert_to_dict(alert),
        "explanation": explanation
    }


@router.get("/{alert_id}/recommendations", summary="Mitigation recommendations")
def get_alert_recommendations(
    alert_id: int,
    db:       Session = Depends(get_db),
    _:        object  = all_authenticated
):
    """Return prioritized mitigation recommendations for a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    recs = get_recommendations_for_threat(alert.threat_type)
    return {
        "alert_id":        alert_id,
        "threat_type":     alert.threat_type,
        "severity":        alert.severity,
        "recommendations": recs,
        "count":           len(recs)
    }


@router.post("/{alert_id}/resolve", summary="Resolve an alert")
def resolve_alert(
    alert_id: int,
    notes:    str   = "Resolved by analyst.",
    db:       Session = Depends(get_db),
    _:        object  = analyst_or_admin
):
    """
    Mark a security alert as resolved with optional resolution notes.
    Requires Analyst or Admin role.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    if alert.resolved:
        return {"detail": "Alert is already resolved.", "alert": alert_to_dict(alert)}

    alert.resolved         = True
    alert.resolution_notes = notes
    db.commit()
    db.refresh(alert)

    return {"detail": "Alert resolved successfully.", "alert": alert_to_dict(alert)}
