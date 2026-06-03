"""
Settings API Routes
===================
REST endpoints for getting and updating user settings.

Endpoints:
  GET /api/settings/  â€” Get current user's settings
  PUT /api/settings/  â€” Update current user's settings

Author: IntelliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User, UserPreferences, UserSession
from ..schemas.settings_schema import UserPreferencesUpdate, UserPreferencesOut
from ..auth import get_current_user

router = APIRouter()

def get_or_create_preferences(db: Session, user_id: int) -> UserPreferences:
    prefs = db.query(UserPreferences).filter(UserPreferences.user_id == user_id).first()
    if not prefs:
        prefs = UserPreferences(user_id=user_id)
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs

@router.get("/", response_model=UserPreferencesOut, summary="Get settings")
def get_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve settings for the logged-in user."""
    return get_or_create_preferences(db, current_user.id)

@router.put("/", response_model=UserPreferencesOut, summary="Update settings")
def update_settings(
    settings_data: UserPreferencesUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update settings for the logged-in user."""
    prefs = get_or_create_preferences(db, current_user.id)
    
    update_data = settings_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(prefs, key, value)
        
    db.commit()
    db.refresh(prefs)
    return prefs

@router.get("/sessions", summary="Get user sessions")
def get_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sessions = db.query(UserSession).filter(UserSession.user_id == current_user.id).all()
    if not sessions:
        # Create a mock current session and mock old session for UI purposes
        current_sess = UserSession(user_id=current_user.id, device="Chrome on Windows", location="New Delhi, India", ip_address="192.168.1.1", is_current=True)
        old_sess1 = UserSession(user_id=current_user.id, device="Safari on iPhone", location="Mumbai, India", ip_address="192.168.1.5", is_current=False)
        old_sess2 = UserSession(user_id=current_user.id, device="Firefox on Mac", location="Bangalore, India", ip_address="192.168.1.10", is_current=False)
        db.add_all([current_sess, old_sess1, old_sess2])
        db.commit()
        sessions = [current_sess, old_sess1, old_sess2]
        
    return {
        "current": [s for s in sessions if s.is_current][0] if any(s.is_current for s in sessions) else None,
        "others": [s for s in sessions if not s.is_current]
    }

@router.delete("/sessions/others", summary="Logout other sessions")
def delete_other_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id, 
        UserSession.is_current == False
    ).delete()
    db.commit()
    return {"message": "All other sessions logged out."}
