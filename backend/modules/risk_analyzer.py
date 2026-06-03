"""
Risk Analyzer Module
====================
Calculates predictive risk scores for entities (Users, IP Addresses)
by aggregating historical alerts, failed logins, and denied accesses.
"""

from sqlalchemy.orm import Session
from collections import defaultdict
import datetime
from ..models import Alert, LoginLog, FileAccessLog

def analyze_entity_risk(db: Session, days_back: int = 7) -> list[dict]:
    """
    Scans the database to identify high-risk entities.
    Returns a sorted list of dictionaries containing the entity, risk score, and contributing factors.
    """
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days_back)
    
    # entity_name -> {"score": int, "factors": dict}
    entities = defaultdict(lambda: {"score": 0, "factors": defaultdict(int)})
    
    # 1. Analyze Alerts (Unresolved or resolved within the timeframe)
    alerts = db.query(Alert).filter(Alert.timestamp >= cutoff).all()
    
    severity_weights = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 5
    }
    
    for alert in alerts:
        source = alert.source
        if not source or source == "System":
            continue
            
        weight = severity_weights.get(alert.severity, 5)
        # Reduce weight slightly if resolved
        if alert.resolved:
            weight = weight // 2
            
        entities[source]["score"] += weight
        entities[source]["factors"][f"{alert.severity} Alerts"] += 1
        
    # 2. Analyze Failed Logins
    failed_logins = db.query(LoginLog).filter(LoginLog.status == "Failed", LoginLog.timestamp >= cutoff).all()
    for login in failed_logins:
        # We can track by username or IP. Let's use IP if available, else username
        source = login.ip_address if login.ip_address else login.username
        if not source:
            continue
            
        entities[source]["score"] += 2
        entities[source]["factors"]["Failed Logins"] += 1
        
    # 3. Analyze Denied File Accesses
    denied_files = db.query(FileAccessLog).filter(FileAccessLog.status == "Denied", FileAccessLog.timestamp >= cutoff).all()
    for access in denied_files:
        source = access.username
        if not source:
            continue
            
        entities[source]["score"] += 2
        entities[source]["factors"]["Denied File Access"] += 1

    # Format output
    result = []
    for entity, data in entities.items():
        if data["score"] > 0:
            # Format factors into a readable string list
            factor_list = [f"{count} {factor}" for factor, count in data["factors"].items() if count > 0]
            
            # Determine Risk Level
            score = data["score"]
            if score >= 80:
                level = "Critical"
                color = "#8b5cf6"  # Purple
            elif score >= 50:
                level = "High"
                color = "#ef4444"  # Red
            elif score >= 25:
                level = "Medium"
                color = "#f59e0b"  # Yellow
            else:
                level = "Low"
                color = "#10b981"  # Green
                
            result.append({
                "entity": entity,
                "score": min(100, score), # Cap at 100 for visual consistency
                "raw_score": score,
                "level": level,
                "color": color,
                "factors": factor_list
            })
            
    # Sort by raw score descending
    result.sort(key=lambda x: x["raw_score"], reverse=True)
    return result
