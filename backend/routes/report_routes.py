"""
Report Generation API Routes
==============================
Endpoints for generating and downloading security reports in PDF and PPT formats.

Endpoints:
  POST /api/reports/pdf   — Generate and download PDF incident report
  POST /api/reports/ppt   — Generate and download PPTX security report
  GET  /api/reports/list  — List all generated report files

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os
import datetime

from ..database import get_db
from ..models   import Alert
from ..auth     import get_current_user, RoleChecker
from ..modules.security_score         import calculate_security_score
from ..modules.recommendation_engine import generate_full_report_recommendations
from ..modules.report_generator       import generate_report

router = APIRouter()

analyst_or_admin  = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))
all_authenticated = Depends(get_current_user)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PDF_DIR  = os.path.join(ROOT_DIR, "reports", "pdf")
PPT_DIR  = os.path.join(ROOT_DIR, "reports", "ppt")


def _get_report_data(db: Session) -> tuple:
    """Fetch all data required to build a report."""
    # Dashboard stats
    from ..models import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog
    total_logs = (
        db.query(LoginLog).count() + db.query(NetworkLog).count() +
        db.query(FileAccessLog).count() + db.query(MalwareLog).count() +
        db.query(USBLog).count()
    )
    active_threats  = db.query(Alert).filter(Alert.resolved == False).count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "Critical", Alert.resolved == False).count()

    stats = {
        "total_logs":      total_logs,
        "active_threats":  active_threats,
        "critical_alerts": critical_alerts
    }

    # Active alerts
    raw_alerts = db.query(Alert).filter(Alert.resolved == False).order_by(Alert.timestamp.desc()).all()
    alerts = [
        {
            "threat_type": a.threat_type,
            "severity":    a.severity,
            "source":      a.source,
            "timestamp":   str(a.timestamp),
            "description": a.description
        }
        for a in raw_alerts
    ]

    # Security score
    score = calculate_security_score(db)

    # Top sources
    from sqlalchemy import func
    top_sources_raw = (
        db.query(Alert.source, func.count(Alert.id).label("count"))
        .filter(Alert.resolved == False)
        .group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    top_sources = [{"source": r.source, "alert_count": r.count} for r in top_sources_raw]

    # Recommendations
    active_threat_types = list({a.threat_type for a in raw_alerts})
    recommendations     = generate_full_report_recommendations(active_threat_types)

    return stats, alerts, score, top_sources, recommendations


@router.post("/generate", summary="Generate a security report (PDF or PPT)")
def generate_report_api(
    format: str = "pdf",
    db: Session = Depends(get_db),
    _:  object  = analyst_or_admin
):
    """
    Generate a security report in the specified format (pdf or ppt) and return it as a downloadable file.
    Requires Analyst or Admin role.
    """
    try:
        stats, alerts, score, top_sources, recommendations = _get_report_data(db)
        filepath = generate_report(format, stats, alerts, score, top_sources, recommendations)
        filename = os.path.basename(filepath)

        media_type = "application/pdf" if format.lower() == "pdf" else "application/vnd.openxmlformats-officedocument.presentationml.presentation"

        return FileResponse(
            path=filepath,
            filename=filename,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/list", summary="List generated reports")
def list_reports(
    _: object = all_authenticated
):
    """List all generated report files (PDF and PPT) with their metadata."""
    reports = []

    for report_type, directory, ext in [("PDF", PDF_DIR, ".pdf"), ("PPT", PPT_DIR, ".pptx")]:
        if os.path.exists(directory):
            for fname in sorted(os.listdir(directory), reverse=True):
                if fname.endswith(ext):
                    fpath = os.path.join(directory, fname)
                    reports.append({
                        "filename":    fname,
                        "type":        report_type,
                        "size_kb":     round(os.path.getsize(fpath) / 1024, 1),
                        "created_at":  datetime.datetime.fromtimestamp(
                            os.path.getctime(fpath)
                        ).isoformat() + "Z"
                    })

    return {"reports": reports, "count": len(reports)}
