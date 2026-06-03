import os
import csv
import datetime

# Resolve paths dynamically to target d:\IntelliSecure\logs\login_logs.csv
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
LOGIN_LOG_FILE = os.path.join(LOGS_DIR, "login_logs.csv")

def log_login_attempt(username: str, ip_address: str, status: str):
    """
    Append a single login attempt to logs/login_logs.csv.
    Ensures safe formatting and directory safety.
    """
    # Ensure logs directory exists
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # Check if the file already exists and is populated
    file_exists = os.path.exists(LOGIN_LOG_FILE) and os.path.getsize(LOGIN_LOG_FILE) > 0
    
    # High-precision ISO timestamp
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    try:
        with open(LOGIN_LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "username", "ip_address", "status"])
            writer.writerow([timestamp, username, ip_address, status])
    except Exception as e:
        # Fallback print to prevent thread failure if system locks file
        print(f"[AUDIT LOG ERROR] Failed to record login attempt for {username} ({status}): {e}")
