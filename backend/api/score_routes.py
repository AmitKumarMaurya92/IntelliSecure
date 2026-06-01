"""
Security Score API Routes
==========================
Endpoints for retrieving the current security health score and trend data.

Endpoints:
  GET /api/score/        — Current security score + risk level + breakdown
  GET /api/score/history — 7-day score trend
  GET /api/score/summary — Quick summary for dashboard cards

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth     import get_current_user
from ..modules.security_score import calculate_security_score

router = APIRouter()

auth = Depends(get_current_user)


@router.get("/", summary="Current security score")
def get_security_score(
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """
    Calculate and return the current security health score (0–100).
    Includes risk level, penalty breakdown, and 7-day trend.
    """
    return calculate_security_score(db)


@router.get("/history", summary="7-day score trend")
def get_score_history(
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """Return the security score trend for the last 7 days."""
    result = calculate_security_score(db)
    return {
        "trend":      result["trend"],
        "current":    result["score"],
        "risk_level": result["risk_level"]
    }


@router.get("/summary", summary="Score card summary")
def get_score_summary(
    db: Session = Depends(get_db),
    _:  object  = auth
):
    """Return minimal score data for the dashboard card widget."""
    result = calculate_security_score(db)
    return {
        "score":      result["score"],
        "risk_level": result["risk_level"],
        "risk_color": result["risk_color"]
    }
