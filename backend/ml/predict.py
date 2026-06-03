"""
ML Anomaly Predictor
======================
Loads the trained Isolation Forest model and runs inference on
log records from the database to detect anomalous behaviour.

Usage (module):
    from ml.predict import detect_anomalies_from_logs
    results = detect_anomalies_from_logs(db)

Author: IntelliSecure Team
"""

import os
import sys
import datetime
import numpy as np

import sys
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

# â”€â”€â”€ Path constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ML_DIR     = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ML_DIR, "anomaly_model.pkl")

# â”€â”€â”€ Lazy model loader (cache in module scope) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_model = None

def _load_model():
    """Load model from disk once and cache it."""
    global _model
    if _model is None:
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
        except Exception as e:
            raise RuntimeError(f"Cannot load ML model from {MODEL_PATH}: {e}")
    return _model


def predict_single(feature_vector: list) -> dict:
    """
    Run prediction on a single feature vector.

    Args:
        feature_vector: List of 7 floats
            [hour_of_day, day_of_week, failed_attempts, status_failed,
             port_number, bytes_ratio, is_external]

    Returns:
        { is_anomaly: bool, anomaly_score: float }
    """
    model     = _load_model()
    X         = np.array(feature_vector).reshape(1, -1)
    prediction = model.predict(X)[0]              # 1 = normal, -1 = anomaly
    score      = model.decision_function(X)[0]    # more negative = more anomalous

    return {
        "is_anomaly":    bool(prediction == -1),
        "anomaly_score": float(round(score, 4))
    }


def _build_login_feature(log) -> list:
    """Extract feature vector from a LoginLog ORM object."""
    ts = log.timestamp
    if isinstance(ts, str):
        ts = ts.replace("Z", "")
        try:
            ts = datetime.datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.datetime.utcnow()

    ip = getattr(log, "ip_address", "192.168.1.1")
    is_external = 0 if (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")) else 1
    status_failed = 1 if getattr(log, "status", "") == "Failed" else 0

    return [
        ts.hour,          # hour_of_day
        ts.weekday(),     # day_of_week
        status_failed,    # failed_attempts proxy
        status_failed,    # status_failed
        0,                # port_number (not applicable for login)
        0.0,              # bytes_ratio (not applicable)
        is_external       # is_external
    ]


def _build_network_feature(log) -> list:
    """Extract feature vector from a NetworkLog ORM object."""
    ts = log.timestamp
    if isinstance(ts, str):
        ts = ts.replace("Z", "")
        try:
            ts = datetime.datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.datetime.utcnow()

    ip = getattr(log, "source_ip", "192.168.1.1")
    is_external = 0 if (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")) else 1
    bytes_sent     = getattr(log, "bytes_sent",     0)
    bytes_received = getattr(log, "bytes_received", 1)
    bytes_ratio    = bytes_sent / (bytes_received + 1)

    return [
        ts.hour,
        ts.weekday(),
        0,              # failed_attempts
        0,              # status_failed
        getattr(log, "port", 0),
        bytes_ratio,
        is_external
    ]


def detect_anomalies_from_logs(db, limit: int = 100) -> list[dict]:
    """
    Run the ML model over recent log records from the database.
    Flags records that score as anomalies.

    Args:
        db:    SQLAlchemy session
        limit: Max number of records to check per log type

    Returns:
        List of anomaly dicts with: log_type, log_id, is_anomaly, anomaly_score, source
    """
    try:
        model = _load_model()
    except RuntimeError:
        # Model not available â€” return empty list gracefully
        return []

    from models import LoginLog, NetworkLog
    anomalies = []

    since = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

    # â”€â”€ Check Login Logs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        login_logs = (
            db.query(LoginLog)
            .filter(LoginLog.timestamp >= since)
            .order_by(LoginLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        for log in login_logs:
            features = _build_login_feature(log)
            result   = predict_single(features)
            if result["is_anomaly"]:
                anomalies.append({
                    "log_type":     "login",
                    "log_id":       log.id,
                    "source":       log.ip_address,
                    "anomaly_score": result["anomaly_score"],
                    "is_anomaly":   True
                })
    except Exception:
        pass

    # â”€â”€ Check Network Logs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        network_logs = (
            db.query(NetworkLog)
            .filter(NetworkLog.timestamp >= since)
            .order_by(NetworkLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        for log in network_logs:
            features = _build_network_feature(log)
            result   = predict_single(features)
            if result["is_anomaly"]:
                anomalies.append({
                    "log_type":     "network",
                    "log_id":       log.id,
                    "source":       log.source_ip,
                    "anomaly_score": result["anomaly_score"],
                    "is_anomaly":   True
                })
    except Exception:
        pass

    return anomalies
