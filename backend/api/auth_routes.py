from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import timedelta

from ..database import get_db
from ..models import User
from ..schemas import UserCreate, UserLogin, UserOut, Token
from ..auth import get_password_hash, verify_password, create_access_token, get_current_user
from ..config import settings
from ..modules.login_logger import log_login_attempt

router = APIRouter()

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user in the system. First user automatically becomes Admin."""
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is already registered."
        )
    
    # Automate role assignment. First user is Admin, others fallback to default input/User role.
    user_count = db.query(User).count()
    assigned_role = user_data.role
    if user_count == 0:
        assigned_role = "Admin"
    elif not assigned_role or assigned_role not in ["Admin", "Analyst", "User"]:
        assigned_role = "User"
        
    hashed_pw = get_password_hash(user_data.password)
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pw,
        role=assigned_role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate credentials, record audit log, and return a session token."""
    # Retrieve client IP, checking reverse proxy X-Forwarded-For first
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")
    
    user = db.query(User).filter(User.username == login_data.username).first()
    
    if not user or not verify_password(login_data.password, user.hashed_password):
        # Audit fail attempt
        log_login_attempt(login_data.username, client_ip, "Failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        # Audit fail attempt for inactive account
        log_login_attempt(user.username, client_ip, "Failed")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is currently deactivated."
        )
        
    # Audit success attempt
    log_login_attempt(user.username, client_ip, "Success")
    
    token_expire_time = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=token_expire_time
    )
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    """Fetch profile data of the currently logged-in user."""
    return current_user

@router.post("/logout")
def logout():
    """Client-side token clearing message helper."""
    return {"detail": "Successfully logged out. Please discard your client token."}
