import datetime
from sqlalchemy import Column, Integer, String, Boolean
from backend.database import Base

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="User", nullable=False)  # "Admin", "Analyst", "User"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String, default=get_current_time, nullable=False)
 
class UserPreferences(Base):
    __tablename__ = "user_preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, index=True, nullable=False)
    
    # Profile
    full_name = Column(String, default="Admin User", nullable=False)
    avatar_base64 = Column(String, nullable=True)

    # Language & Region
    language = Column(String, default="English (US)", nullable=False)
    timezone = Column(String, default="(UTC+05:30) Asia/Kolkata", nullable=False)
    
    # Data & Logs
    log_retention_days = Column(Integer, default=90, nullable=False)
    auto_delete_logs = Column(Boolean, default=True, nullable=False)
    compress_old_logs = Column(Boolean, default=True, nullable=False)
    
    # System Preferences
    auto_refresh_interval = Column(Integer, default=10, nullable=False)
    sound_alerts = Column(Boolean, default=True, nullable=False)
    show_security_tips = Column(Boolean, default=True, nullable=False)
    dark_mode = Column(Boolean, default=True, nullable=False)

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    device = Column(String, nullable=False)
    location = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    started_at = Column(String, default=get_current_time, nullable=False)
    is_current = Column(Boolean, default=False, nullable=False)