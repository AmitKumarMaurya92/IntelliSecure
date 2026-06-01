import os
import csv
import datetime
from sqlalchemy.orm import Session
from ..models import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog

# Resolve absolute path to logs directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def parse_iso_datetime(dt_str: str) -> datetime.datetime:
    """Parse standard ISO-8601 datetime strings with standard datetime.fromisoformat, with fallback."""
    if not dt_str:
        return datetime.datetime.utcnow()
    # Strip Z to standard format if needed
    cleaned = dt_str.replace("Z", "")
    try:
        return datetime.datetime.fromisoformat(cleaned)
    except Exception:
        return datetime.datetime.utcnow()

def sync_login_logs(db: Session) -> int:
    csv_path = os.path.join(LOGS_DIR, "login_logs.csv")
    if not os.path.exists(csv_path):
        return 0
    
    count = 0
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_iso_datetime(row.get("timestamp"))
                username = row.get("username", "").strip()
                ip_address = row.get("ip_address", "").strip()
                status = row.get("status", "").strip()
                
                if not username:
                    continue
                
                # Deduplication check
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
    if not os.path.exists(csv_path):
        return 0
    
    count = 0
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_iso_datetime(row.get("timestamp"))
                source_ip = row.get("source_ip", "").strip()
                destination_ip = row.get("destination_ip", "").strip()
                port_str = row.get("port", "0").strip()
                port = int(port_str) if port_str.isdigit() else 0
                protocol = row.get("protocol", "").strip()
                
                bytes_sent_str = row.get("bytes_sent", "0").strip()
                bytes_sent = int(bytes_sent_str) if bytes_sent_str.isdigit() else 0
                
                bytes_received_str = row.get("bytes_received", "0").strip()
                bytes_received = int(bytes_received_str) if bytes_received_str.isdigit() else 0
                
                action = row.get("action", "").strip()
                
                if not source_ip or not destination_ip:
                    continue
                
                # Deduplication check
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
    if not os.path.exists(csv_path):
        return 0
    
    count = 0
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_iso_datetime(row.get("timestamp"))
                username = row.get("username", "").strip()
                file_path = row.get("file_path", "").strip()
                access_type = row.get("access_type", "").strip()
                status = row.get("status", "").strip()
                
                if not username or not file_path:
                    continue
                
                # Deduplication check
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
    if not os.path.exists(csv_path):
        return 0
    
    count = 0
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_iso_datetime(row.get("timestamp"))
                file_name = row.get("file_name", "").strip()
                file_path = row.get("file_path", "").strip()
                file_hash = row.get("hash", "").strip()
                signature = row.get("signature", "").strip()
                action_taken = row.get("action_taken", "").strip()
                
                if not file_hash:
                    continue
                
                # Deduplication check
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
    if not os.path.exists(csv_path):
        return 0
    
    count = 0
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_iso_datetime(row.get("timestamp"))
                username = row.get("username", "").strip()
                device_name = row.get("device_name", "").strip()
                device_id = row.get("device_id", "").strip()
                action = row.get("action", "").strip()
                
                if not device_id:
                    continue
                
                # Deduplication check
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
