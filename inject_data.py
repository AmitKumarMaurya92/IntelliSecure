import sys
import os
from datetime import datetime, timedelta

# Add backend directory to path so we can import its modules
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))

from backend.database import SessionLocal, engine, Base
from backend.models import LoginLog, NetworkLog, FileAccessLog, MalwareLog, USBLog

def inject_mock_data():
    print("Connecting to database...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    now = datetime.utcnow()

    print("Injecting Brute Force attempts...")
    # Inject 15 failed logins from the same IP
    for i in range(15):
        ts = (now - timedelta(minutes=5) + timedelta(seconds=i*5)).isoformat()
        db.add(LoginLog(timestamp=ts, username="admin", ip_address="192.168.1.105", status="Failed"))

    print("Injecting Port Scan activity...")
    # Inject network logs hitting many different ports from the same IP
    for port in range(8000, 8025):
        ts = (now - timedelta(minutes=3)).isoformat()
        db.add(NetworkLog(timestamp=ts, source_ip="10.0.0.55", destination_ip="192.168.1.10", 
                          port=port, protocol="TCP", bytes_sent=40, bytes_received=0, action="Block"))

    print("Injecting Unauthorized File Access...")
    # Inject unauthorized file access
    ts = (now - timedelta(minutes=2)).isoformat()
    db.add(FileAccessLog(timestamp=ts, username="guest_user", file_path="/etc/shadow", access_type="Read", status="Denied"))
    db.add(FileAccessLog(timestamp=ts, username="guest_user", file_path="/etc/passwd", access_type="Write", status="Denied"))

    print("Injecting Blocked USB Device...")
    ts = (now - timedelta(minutes=1)).isoformat()
    db.add(USBLog(timestamp=ts, username="employee12", device_name="Unknown Mass Storage", device_id="USB/VID_1234&PID_5678", action="Blocked"))

    db.commit()
    db.close()
    print("✅ Successfully injected mock data into intelisecure.db")
    print("You can now run a scan from the Real-Time Monitor dashboard!")

if __name__ == "__main__":
    inject_mock_data()
