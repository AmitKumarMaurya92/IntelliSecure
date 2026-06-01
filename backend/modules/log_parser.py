import os
import pandas as pd
import datetime
from sqlalchemy.orm import Session
from ..models import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog

# Resolve absolute path to logs directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def parse_iso_datetime(dt_str) -> datetime.datetime:
    """Parse standard ISO-8601 datetime strings."""
    if pd.isna(dt_str) or not dt_str:
        return datetime.datetime.utcnow()
    try:
        # Assuming dt_str is already a string
        cleaned = str(dt_str).replace("Z", "")
        return datetime.datetime.fromisoformat(cleaned)
    except Exception:
        return datetime.datetime.utcnow()

def sync_login_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "login_logs.csv")
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        return 0
    
    count = 0
    try:
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            timestamp = parse_iso_datetime(row.get("timestamp"))
            username = str(row.get("username", "")).strip()
            ip_address = str(row.get("ip_address", "")).strip()
            status = str(row.get("status", "")).strip()
            
            if not username or pd.isna(username) or username == 'nan':
                continue
                
            exists = db.query(LoginLog).filter(
                LoginLog.timestamp == timestamp,
                LoginLog.username == username,
                LoginLog.ip_address == ip_address,
                LoginLog.status == status
            ).first()
            
            if not exists:
                log_entry = LoginLog(
                    timestamp=timestamp,
                    username=username,
                    ip_address=ip_address,
                    status=status
                )
                db.add(log_entry)
                count += 1
        db.commit()
    except Exception as e:
        print(f"Error syncing login logs: {e}")
        db.rollback()
    return count

def sync_network_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "network_logs.csv")
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        return 0
    
    count = 0
    try:
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            timestamp = parse_iso_datetime(row.get("timestamp"))
            source_ip = str(row.get("source_ip", "")).strip()
            destination_ip = str(row.get("destination_ip", "")).strip()
            port = int(row.get("port", 0)) if pd.notna(row.get("port")) else 0
            protocol = str(row.get("protocol", "")).strip()
            bytes_sent = int(row.get("bytes_sent", 0)) if pd.notna(row.get("bytes_sent")) else 0
            bytes_received = int(row.get("bytes_received", 0)) if pd.notna(row.get("bytes_received")) else 0
            action = str(row.get("action", "")).strip()
            
            if not source_ip or source_ip == 'nan' or not destination_ip or destination_ip == 'nan':
                continue
                
            exists = db.query(NetworkLog).filter(
                NetworkLog.timestamp == timestamp,
                NetworkLog.source_ip == source_ip,
                NetworkLog.destination_ip == destination_ip,
                NetworkLog.port == port,
                NetworkLog.protocol == protocol,
                NetworkLog.action == action
            ).first()
            
            if not exists:
                log_entry = NetworkLog(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    port=port,
                    protocol=protocol,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    action=action
                )
                db.add(log_entry)
                count += 1
        db.commit()
    except Exception as e:
        print(f"Error syncing network logs: {e}")
        db.rollback()
    return count

def sync_file_access_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "file_access_logs.csv")
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        return 0
    
    count = 0
    try:
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            timestamp = parse_iso_datetime(row.get("timestamp"))
            username = str(row.get("username", "")).strip()
            file_path = str(row.get("file_path", "")).strip()
            access_type = str(row.get("access_type", "")).strip()
            status = str(row.get("status", "")).strip()
            
            if not username or username == 'nan' or not file_path or file_path == 'nan':
                continue
                
            exists = db.query(FileAccessLog).filter(
                FileAccessLog.timestamp == timestamp,
                FileAccessLog.username == username,
                FileAccessLog.file_path == file_path,
                FileAccessLog.access_type == access_type,
                FileAccessLog.status == status
            ).first()
            
            if not exists:
                log_entry = FileAccessLog(
                    timestamp=timestamp,
                    username=username,
                    file_path=file_path,
                    access_type=access_type,
                    status=status
                )
                db.add(log_entry)
                count += 1
        db.commit()
    except Exception as e:
        print(f"Error syncing file access logs: {e}")
        db.rollback()
    return count

def sync_malware_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "malware_logs.csv")
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        return 0
    
    count = 0
    try:
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            timestamp = parse_iso_datetime(row.get("timestamp"))
            file_name = str(row.get("file_name", "")).strip()
            file_path = str(row.get("file_path", "")).strip()
            file_hash = str(row.get("hash", "")).strip()
            signature = str(row.get("signature", "")).strip()
            action_taken = str(row.get("action_taken", "")).strip()
            
            if not file_hash or file_hash == 'nan':
                continue
                
            exists = db.query(MalwareLog).filter(
                MalwareLog.timestamp == timestamp,
                MalwareLog.hash == file_hash,
                MalwareLog.signature == signature
            ).first()
            
            if not exists:
                log_entry = MalwareLog(
                    timestamp=timestamp,
                    file_name=file_name,
                    file_path=file_path,
                    hash=file_hash,
                    signature=signature,
                    action_taken=action_taken
                )
                db.add(log_entry)
                count += 1
        db.commit()
    except Exception as e:
        print(f"Error syncing malware logs: {e}")
        db.rollback()
    return count

def sync_usb_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "usb_logs.csv")
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        return 0
    
    count = 0
    try:
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            timestamp = parse_iso_datetime(row.get("timestamp"))
            username = str(row.get("username", "")).strip()
            device_name = str(row.get("device_name", "")).strip()
            device_id = str(row.get("device_id", "")).strip()
            action = str(row.get("action", "")).strip()
            
            if not device_id or device_id == 'nan':
                continue
                
            exists = db.query(USBLog).filter(
                USBLog.timestamp == timestamp,
                USBLog.device_id == device_id,
                USBLog.action == action
            ).first()
            
            if not exists:
                log_entry = USBLog(
                    timestamp=timestamp,
                    username=username,
                    device_name=device_name,
                    device_id=device_id,
                    action=action
                )
                db.add(log_entry)
                count += 1
        db.commit()
    except Exception as e:
        print(f"Error syncing USB logs: {e}")
        db.rollback()
    return count

def sync_all_logs(db: Session) -> dict:
    """Trigger synchronization on all 5 CSV logs into database, returning record counts."""
    results = {}
    results["login"] = sync_login_logs(db)
    results["network"] = sync_network_logs(db)
    results["file"] = sync_file_access_logs(db)
    results["malware"] = sync_malware_logs(db)
    results["usb"] = sync_usb_logs(db)
    results["total_synced"] = (
        results["login"] + results["network"] + results["file"] + results["malware"] + results["usb"]
    )
    return results
