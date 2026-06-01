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
