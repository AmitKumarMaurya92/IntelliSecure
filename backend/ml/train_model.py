"""
ML Model Training Script â€” Isolation Forest Anomaly Detector
==============================================================
Trains an Isolation Forest model on login and network log features.
Detects anomalous behaviour that doesn't match the established baseline.

Features Used:
  - hour_of_day:       Time of day (0â€“23)
  - day_of_week:       Day (0=Monday, 6=Sunday)
  - failed_attempts:   Number of failed logins in last 5 min from same IP
  - port_number:       Network port contacted (0 for login events)
  - bytes_ratio:       bytes_sent / (bytes_received + 1) â€” ratio anomaly
  - is_external_ip:    1 if source IP is outside 192.168.x.x (external)

Usage:
    python train_model.py

Output:
    backend/ml/anomaly_model.pkl

Author: IntelliSecure Team
"""

import os
import sys
import csv
import joblib
import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# â”€â”€â”€ Path setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ML_DIR       = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR  = os.path.dirname(ML_DIR)
ROOT_DIR     = os.path.dirname(BACKEND_DIR)
DATASET_PATH = os.path.join(ROOT_DIR, "datasets", "training_logs.csv")
MODEL_PATH   = os.path.join(ML_DIR, "anomaly_model.pkl")


def extract_features(row: dict) -> list:
    """
    Convert a raw CSV log row into a numeric feature vector.
    Handles both login log rows and network log rows.
    """
    # â”€â”€ Timestamp features â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ts_str = row.get("timestamp", "").replace("Z", "").strip()
    try:
        ts = datetime.datetime.fromisoformat(ts_str)
    except Exception:
        ts = datetime.datetime.utcnow()

    hour_of_day  = ts.hour
    day_of_week  = ts.weekday()

    # â”€â”€ Login-specific features â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    failed_attempts = int(row.get("failed_attempts", 0))
    status_failed   = 1 if row.get("status", "").lower() == "failed" else 0

    # â”€â”€ Network-specific features â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    port_number    = int(row.get("port", 0))
    bytes_sent     = int(row.get("bytes_sent", 0))
    bytes_received = int(row.get("bytes_received", 1))
    bytes_ratio    = bytes_sent / (bytes_received + 1)

    # â”€â”€ IP classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ip = row.get("source_ip", row.get("ip_address", "192.168.1.1"))
    is_external = 0 if (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")) else 1

    return [
        hour_of_day,    # 0â€“23
        day_of_week,    # 0â€“6
        failed_attempts,
        status_failed,
        port_number,
        bytes_ratio,
        is_external
    ]


def load_training_data(csv_path: str) -> pd.DataFrame:
    """Load training data from CSV and extract feature vectors."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training dataset not found: {csv_path}")

    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                features = extract_features(row)
                rows.append(features)
            except Exception as e:
                print(f"  [SKIP] Error processing row: {e}")
                continue

    if not rows:
        raise ValueError("No valid training rows found in dataset.")

    columns = ["hour_of_day", "day_of_week", "failed_attempts",
               "status_failed", "port_number", "bytes_ratio", "is_external"]

    return pd.DataFrame(rows, columns=columns)


def train_model(csv_path: str = DATASET_PATH, model_path: str = MODEL_PATH):
    """
    Train the Isolation Forest model and save it to disk.

    Args:
        csv_path:   Path to training CSV
        model_path: Path to save the trained model (.pkl)
    """
    print(f"\n{'='*55}")
    print("  IntelliSecure â€” ML Anomaly Detector Training")
    print(f"{'='*55}")
    print(f"  Dataset:  {csv_path}")
    print(f"  Model:    {model_path}")

    # â”€â”€ Load data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print("\n[1/4] Loading training data...")
    df = load_training_data(csv_path)
    print(f"  Loaded {len(df)} training samples.")
    print(f"  Features: {list(df.columns)}")
    print(f"  Sample stats:\n{df.describe().round(2)}")

    X = df.values

    # â”€â”€ Build pipeline: Scaler + Isolation Forest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print("\n[2/4] Building model pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("model",  IsolationForest(
            n_estimators=200,
            contamination=0.08,   # Expect ~8% anomalies in training data
            max_features=1.0,
            random_state=42,
            n_jobs=-1             # Use all CPU cores
        ))
    ])

    # â”€â”€ Train â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print("\n[3/4] Training Isolation Forest...")
    pipeline.fit(X)

    # Quick evaluation on training set (anomaly = -1, normal = 1)
    preds   = pipeline.predict(X)
    n_anomalies = (preds == -1).sum()
    print(f"  Flagged {n_anomalies} training samples as anomalies ({n_anomalies/len(X)*100:.1f}%)")

    # â”€â”€ Save model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[4/4] Saving model to {model_path}...")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(pipeline, model_path)
    print(f"  Model saved. Size: {os.path.getsize(model_path):,} bytes")

    print(f"\n{'='*55}")
    print("  Training complete! [DONE]")
    print(f"{'='*55}\n")

    return pipeline


if __name__ == "__main__":
    train_model()
