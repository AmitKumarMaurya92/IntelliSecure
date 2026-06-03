"""
User Management API Routes
============================
REST endpoints for managing user accounts, roles, and status.

Endpoints:
  GET  /api/users/            — List all users
  POST /api/users/{id}/role   — Change user role (Admin only)
  POST /api/users/{id}/status — Toggle active status (Admin only)

Author: InteliSecure Team
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models.user import User
from ..schemas.user_schema import UserOut
from ..auth import get_current_user, RoleChecker

router = APIRouter()

# Role dependencies
admin_only = Depends(RoleChecker(allowed_roles=["Admin"]))
all_authenticated = Depends(get_current_user)

@router.get("/", response_model=List[UserOut], summary="List all users")
def list_users(
    db: Session = Depends(get_db),
    _: object = all_authenticated
):
    """Retrieve all users in the system."""
    return db.query(User).all()

@router.post("/{user_id}/role", response_model=UserOut, summary="Change user role")
def change_user_role(
    user_id: int,
    role: str,
    db: Session = Depends(get_db),
    current_user: User = admin_only
):
    """Change the role of a user (Admin, Analyst, User). Only accessible by Admins."""
    if role not in ["Admin", "Analyst", "User"]:
        raise HTTPException(status_code=400, detail="Invalid role specified.")
        
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    if target_user.id == current_user.id and role != "Admin":
        raise HTTPException(status_code=400, detail="You cannot demote yourself.")
        
    target_user.role = role
    db.commit()
    db.refresh(target_user)
    return target_user

@router.post("/{user_id}/status", response_model=UserOut, summary="Toggle active status")
def toggle_user_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = admin_only
):
    """Toggle a user's active status (activate/deactivate). Only accessible by Admins."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
        
    target_user.is_active = not target_user.is_active
    db.commit()
    db.refresh(target_user)
    return target_user
