import datetime
from sqlalchemy.orm import Session
from ..models import Alert

def create_alert(db: Session, threat_type: str, severity: str, source: str, description: str) -> Alert:
    """
    Creates and records a security alert in the database.
    Includes built-in alert deduplication: checks if an active alert of the same 
    type and source occurred in the last 5 minutes to avoid flood fatigue.
    """
    time_window = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Check for identical duplicate active alerts in the last 5 minutes
    duplicate = db.query(Alert).filter(
        Alert.threat_type == threat_type,
        Alert.source == source,
        Alert.resolved == False,
        Alert.timestamp >= time_window
    ).first()
    
    if duplicate:
        # Update description and bump timestamp to show continuation
        duplicate.timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        duplicate.description = description
        db.commit()
        db.refresh(duplicate)
        return duplicate
        
    new_alert = Alert(
        threat_type=threat_type,
        severity=severity,
        source=source,
        description=description,
        resolved=False
    )
    
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    return new_alert

def resolve_alert(db: Session, alert_id: int, notes: str) -> Alert:
    """Resolves an active security alert with analyst resolution details."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.resolved = True
        alert.resolution_notes = notes
        db.commit()
        db.refresh(alert)
    return alert
