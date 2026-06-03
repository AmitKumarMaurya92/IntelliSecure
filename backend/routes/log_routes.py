from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from ..database import get_db
from ..models import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog, get_current_time
from ..auth import get_current_user, RoleChecker
from ..modules.log_parser import sync_all_logs
from ..schemas.log_schema import (
    LoginLogCreate, NetworkLogCreate, FileAccessLogCreate, 
    MalwareLogCreate, USBLogCreate
)

router = APIRouter()

# Restrict log synchronization to Administrators and Analysts
auth_analyst_admin = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))
# Read access is open to all authenticated users
auth_all = Depends(get_current_user)

@router.post("/sync", status_code=status.HTTP_200_OK)
def sync_telemetry_logs(db: Session = Depends(get_db), current_user=auth_analyst_admin):
    """Parse local telemetry CSVs and load unique records into the database."""
    sync_stats = sync_all_logs(db)
    return {"message": "Telemetry synchronization finished.", "stats": sync_stats}

# --- DYNAMIC LOG INGESTION ENDPOINTS ---

@router.post("/ingest/login", status_code=status.HTTP_201_CREATED)
def ingest_login_log(log: LoginLogCreate, db: Session = Depends(get_db)):
    """Ingest a live login event from an external system."""
    new_log = LoginLog(
        timestamp=log.timestamp or get_current_time(),
        username=log.username,
        ip_address=log.ip_address,
        status=log.status
    )
    db.add(new_log)
    db.commit()
    return {"message": "Login log ingested successfully"}

@router.post("/ingest/network", status_code=status.HTTP_201_CREATED)
def ingest_network_log(log: NetworkLogCreate, db: Session = Depends(get_db)):
    """Ingest a live network packet event."""
    new_log = NetworkLog(
        timestamp=log.timestamp or get_current_time(),
        source_ip=log.source_ip,
        destination_ip=log.destination_ip,
        port=log.port,
        protocol=log.protocol,
        bytes_sent=log.bytes_sent,
        bytes_received=log.bytes_received,
        action=log.action
    )
    db.add(new_log)
    db.commit()
    return {"message": "Network log ingested successfully"}

@router.post("/ingest/file", status_code=status.HTTP_201_CREATED)
def ingest_file_log(log: FileAccessLogCreate, db: Session = Depends(get_db)):
    """Ingest a live file access event."""
    new_log = FileAccessLog(
        timestamp=log.timestamp or get_current_time(),
        username=log.username,
        file_path=log.file_path,
        access_type=log.access_type,
        status=log.status
    )
    db.add(new_log)
    db.commit()
    return {"message": "File access log ingested successfully"}

@router.post("/ingest/malware", status_code=status.HTTP_201_CREATED)
def ingest_malware_log(log: MalwareLogCreate, db: Session = Depends(get_db)):
    """Ingest a live malware detection event."""
    try:
        new_log = MalwareLog(
            timestamp=log.timestamp or get_current_time(),
            file_name=log.file_name,
            file_path=log.file_path,
            hash=log.hash,
            signature=log.signature,
            action_taken=log.action
        )
        db.add(new_log)
        db.commit()
        return {"message": "Malware log ingested successfully"}
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}

@router.post("/ingest/usb", status_code=status.HTTP_201_CREATED)
def ingest_usb_log(log: USBLogCreate, db: Session = Depends(get_db)):
    """Ingest a live USB device event."""
    new_log = USBLog(
        timestamp=log.timestamp or get_current_time(),
        username=log.username,
        device_name=log.device_name,
        device_id=log.device_id,
        action=log.action
    )
    db.add(new_log)
    db.commit()
    return {"message": "USB log ingested successfully"}


@router.get("/stats", status_code=status.HTTP_200_OK)
def get_log_statistics(db: Session = Depends(get_db), current_user=auth_all):
    """Aggregate total record counts across all five database tables."""
    login_c = db.query(LoginLog).count()
    network_c = db.query(NetworkLog).count()
    file_c = db.query(FileAccessLog).count()
    malware_c = db.query(MalwareLog).count()
    usb_c = db.query(USBLog).count()
    
    total = login_c + network_c + file_c + malware_c + usb_c
    
    return {
        "total": total,
        "by_type": {
            "login": login_c,
            "network": network_c,
            "file_access": file_c,
            "malware": malware_c,
            "usb": usb_c
        }
    }

@router.get("/login")
def get_login_logs(
    limit: int = 50, offset: int = 0, status_filter: Optional[str] = None, 
    db: Session = Depends(get_db), current_user=auth_all
):
    """Query login attempts from database with search parameters."""
    query = db.query(LoginLog)
    if status_filter:
        query = query.filter(LoginLog.status == status_filter)
    logs = query.order_by(LoginLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [{
        "id": l.id,
        "timestamp": str(l.timestamp),
        "username": l.username,
        "ip_address": l.ip_address,
        "status": l.status
    } for l in logs]

@router.get("/network")
def get_network_logs(
    limit: int = 50, offset: int = 0, action_filter: Optional[str] = None, 
    db: Session = Depends(get_db), current_user=auth_all
):
    """Query network packet logs from database with search parameters."""
    query = db.query(NetworkLog)
    if action_filter:
        query = query.filter(NetworkLog.action == action_filter)
    logs = query.order_by(NetworkLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [{
        "id": l.id,
        "timestamp": str(l.timestamp),
        "source_ip": l.source_ip,
        "destination_ip": l.destination_ip,
        "port": l.port,
        "protocol": l.protocol,
        "bytes_sent": l.bytes_sent,
        "bytes_received": l.bytes_received,
        "action": l.action
    } for l in logs]

@router.get("/file")
def get_file_access_logs(
    limit: int = 50, offset: int = 0, status_filter: Optional[str] = None, 
    db: Session = Depends(get_db), current_user=auth_all
):
    """Query file operations from database with search parameters."""
    query = db.query(FileAccessLog)
    if status_filter:
        query = query.filter(FileAccessLog.status == status_filter)
    logs = query.order_by(FileAccessLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [{
        "id": l.id,
        "timestamp": str(l.timestamp),
        "username": l.username,
        "file_path": l.file_path,
        "access_type": l.access_type,
        "status": l.status
    } for l in logs]

@router.get("/malware")
def get_malware_logs(
    limit: int = 50, offset: int = 0, action_filter: Optional[str] = None, 
    db: Session = Depends(get_db), current_user=auth_all
):
    """Query quarantined malware logs from database with search parameters."""
    query = db.query(MalwareLog)
    if action_filter:
        query = query.filter(MalwareLog.action_taken == action_filter)
    logs = query.order_by(MalwareLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [{
        "id": l.id,
        "timestamp": str(l.timestamp),
        "file_name": l.file_name,
        "file_path": l.file_path,
        "hash": l.hash,
        "signature": l.signature,
        "action_taken": l.action_taken
    } for l in logs]

@router.get("/usb")
def get_usb_logs(
    limit: int = 50, offset: int = 0, action_filter: Optional[str] = None, 
    db: Session = Depends(get_db), current_user=auth_all
):
    """Query hardware USB event logs from database with search parameters."""
    query = db.query(USBLog)
    if action_filter:
        query = query.filter(USBLog.action == action_filter)
    logs = query.order_by(USBLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [{
        "id": l.id,
        "timestamp": str(l.timestamp),
        "username": l.username,
        "device_name": l.device_name,
        "device_id": l.device_id,
        "action": l.action
    } for l in logs]
