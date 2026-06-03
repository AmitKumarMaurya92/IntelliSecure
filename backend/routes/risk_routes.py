"""
Risk Analysis API Routes
========================
Endpoints for retrieving predictive risk analysis data.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_user
from ..modules.risk_analyzer import analyze_entity_risk

router = APIRouter()
auth = Depends(get_current_user)

@router.get("/entities", summary="Get high-risk entities")
def get_high_risk_entities(
    days: int = 7,
    limit: int = 10,
    db: Session = Depends(get_db),
    _: object = auth
):
    """
    Returns a list of the most high-risk entities (Users/IPs) based on historical behavior.
    """
    results = analyze_entity_risk(db, days_back=days)
    
    # Return top N results
    return {"entities": results[:limit], "total_analyzed": len(results)}
