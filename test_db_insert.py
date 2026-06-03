import sys
import os

# Add the workspace root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database import SessionLocal
from backend.models import MalwareLog

db = SessionLocal()
try:
    print("Attempting to insert a MalwareLog...")
    new_log = MalwareLog(
        timestamp="2026-06-04 03:40:00",
        file_name="mimikatz.exe",
        file_path="C:\\Users\\Downloads\\mimikatz.exe",
        hash="a1b2c3d4e5f6g7h8i9j0",
        signature="Trojan.Mimikatz",
        action_taken="Quarantined"
    )
    db.add(new_log)
    db.commit()
    print("Success!")
except Exception as e:
    import traceback
    print("Error during insertion:")
    traceback.print_exc()
finally:
    db.close()
