from fastapi import APIRouter
from typing import List, Dict, Any

router = APIRouter()

@router.get("/dashboard/stats")
def dashboard_stats() -> Dict[str, Any]:
    return {
        "total_logs": 24532,
        "active_threats": 28,
        "critical_alerts": 7,
        "security_score": 87
    }

@router.get("/alerts")
def alerts() -> List[Dict[str, str]]:
    return [
        {
            "threat": "Brute Force Attack",
            "severity": "High",
            "time": "10:35 AM"
        },
        {
            "threat": "Port Scan",
            "severity": "Medium",
            "time": "09:22 AM"
        },
        {
            "threat": "Unauthorized Access",
            "severity": "High",
            "time": "08:45 AM"
        },
        {
            "threat": "Malware Activity",
            "severity": "Low",
            "time": "08:10 AM"
        }
    ]
