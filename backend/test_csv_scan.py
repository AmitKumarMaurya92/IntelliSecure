import sys
import os
import datetime

# Add the backend directory to sys.path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database import SessionLocal, engine, Base
from backend.models import LoginLog, Alert, NetworkLog, FileAccessLog, MalwareLog, USBLog
from backend.modules.log_parser import sync_all_logs
from backend.modules.realtime_monitor import run_all_detectors

def main():
    print("Initializing test...")
    db = SessionLocal()
    
    try:
        # Clear existing logs and alerts for a clean test
        db.query(LoginLog).delete()
        db.query(Alert).delete()
        db.commit()
        print("Cleared existing LoginLogs and Alerts.")
        
        # 1. Sync the CSVs
        print("Syncing CSVs to Database...")
        sync_stats = sync_all_logs(db)
        print("Sync stats:", sync_stats)
        
        # Adjust timestamps dynamically so they appear as "just happened"
        import datetime
        now = datetime.datetime.utcnow()
        logs = db.query(LoginLog).order_by(LoginLog.timestamp.desc()).all()
        if logs:
            max_ts = max(l.timestamp if isinstance(l.timestamp, datetime.datetime) else datetime.datetime.fromisoformat(l.timestamp.replace('Z', '')) for l in logs)
            time_diff = now - max_ts
            for l in logs:
                curr_ts = l.timestamp if isinstance(l.timestamp, datetime.datetime) else datetime.datetime.fromisoformat(l.timestamp.replace('Z', ''))
                l.timestamp = curr_ts + time_diff
            db.commit()
            print("Adjusted timestamps to be within the current time window.")
        
        # 2. Run Detectors
        print("\nRunning Threat Detectors...")
        scan_results = run_all_detectors(db)
        print("Scan Results:")
        for key, val in scan_results.items():
            print(f"  {key}: {val}")
        
        # 3. Fetch and print the generated alerts
        print("\nGenerated Alerts in DB:")
        alerts = db.query(Alert).all()
        if not alerts:
            print("  No alerts were generated from this dataset.")
        else:
            for a in alerts:
                print(f"  [{a.severity}] {a.threat_type} (Source: {a.source})")
                print(f"    {a.description}")
                print(f"    Time: {a.timestamp}\n")
                
    except Exception as e:
        print("Error during testing:", e)
    finally:
        db.close()

if __name__ == "__main__":
    main()
