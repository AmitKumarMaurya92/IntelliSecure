from pydantic import BaseModel
from typing import Optional

class UserPreferencesUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_base64: Optional[str] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    log_retention_days: Optional[int] = None
    auto_delete_logs: Optional[bool] = None
    compress_old_logs: Optional[bool] = None
    auto_refresh_interval: Optional[int] = None
    sound_alerts: Optional[bool] = None
    show_security_tips: Optional[bool] = None
    dark_mode: Optional[bool] = None

class UserPreferencesOut(BaseModel):
    id: int
    user_id: int
    full_name: str
    avatar_base64: Optional[str] = None
    language: str
    timezone: str
    log_retention_days: int
    auto_delete_logs: bool
    compress_old_logs: bool
    auto_refresh_interval: int
    sound_alerts: bool
    show_security_tips: bool
    dark_mode: bool

    class Config:
        from_attributes = True
