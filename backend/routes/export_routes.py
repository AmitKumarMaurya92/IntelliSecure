"""
Export API Routes
=================
REST endpoints for exporting raw database tables into CSV and Excel formats.
Optimized for data analysts and BI tools.

Endpoints:
  GET /api/export/{dataset} â€” Export dataset (format: csv|xlsx)

Author: IntelliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import pandas as pd
import io
import datetime

from ..database import get_db
from ..models import Alert, LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog
from ..routes import device_routes
from ..auth import get_current_user, RoleChecker

router = APIRouter()

analyst_or_admin = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))

def get_dataset_query(dataset: str, db: Session):
    if dataset == "threats":
        return db.query(Alert)
    elif dataset == "login_logs":
        return db.query(LoginLog)
    elif dataset == "network_logs":
        return db.query(NetworkLog)
    elif dataset == "file_logs":
        return db.query(FileAccessLog)
    elif dataset == "malware_logs":
        return db.query(MalwareLog)
    elif dataset == "usb_logs":
        return db.query(USBLog)
    else:
        raise ValueError(f"Unknown dataset: {dataset}")

@router.get("/{dataset}", summary="Export raw dataset to CSV or Excel")
def export_dataset(
    dataset: str,
    format: str = Query("csv", description="Format: 'csv' or 'xlsx'"),
    limit: int = Query(10000, description="Max rows to export"),
    db: Session = Depends(get_db),
    _: object = analyst_or_admin
):
    """
    Export raw data for analytics.
    Supported datasets: threats, login_logs, network_logs, file_logs, malware_logs, usb_logs, devices.
    """
    format = format.lower()
    if format not in ["csv", "xlsx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'csv' or 'xlsx'.")

    try:
        if dataset == "devices":
            devices_list = device_routes._last_scan_result.get("devices", [])
            df = pd.DataFrame(devices_list)
        else:
            query = get_dataset_query(dataset, db).limit(limit)
            df = pd.read_sql(query.statement, query.session.bind)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data retrieval failed: {str(e)}")

    if df.empty:
        raise HTTPException(status_code=404, detail="Dataset is empty.")

    # Format datetime columns nicely
    for col in df.select_dtypes(include=['datetime64']).columns:
        df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"intelisecure_export_{dataset}_{timestamp}"

    buffer = io.BytesIO()

    if format == "csv":
        df.to_csv(buffer, index=False)
        media_type = "text/csv"
        filename += ".csv"
    else:
        with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name=dataset.capitalize())
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename += ".xlsx"

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
