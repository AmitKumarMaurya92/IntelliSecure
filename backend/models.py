import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="User", nullable=False)  # "Admin", "Analyst", "User"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String, index=True, nullable=False)
    ip_address = Column(String, nullable=False)
    status = Column(String, nullable=False)  # "Success", "Failed"

class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    source_ip = Column(String, index=True, nullable=False)
    destination_ip = Column(String, index=True, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)  # "TCP", "UDP", "ICMP"
    bytes_sent = Column(Integer, nullable=False)
    bytes_received = Column(Integer, nullable=False)
    action = Column(String, nullable=False)  # "Allow", "Block", "Flagged"

class FileAccessLog(Base):
    __tablename__ = "file_access_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String, index=True, nullable=False)
    file_path = Column(String, nullable=False)
    access_type = Column(String, nullable=False)  # "Read", "Write", "Delete"
    status = Column(String, nullable=False)  # "Allowed", "Denied"

class MalwareLog(Base):
    __tablename__ = "malware_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    hash = Column(String, index=True, nullable=False)
    signature = Column(String, nullable=False)  # Name of detected threat signature
    action_taken = Column(String, nullable=False)  # "Quarantined", "Deleted", "Ignored"

class USBLog(Base):
    __tablename__ = "usb_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String, index=True, nullable=False)
    device_name = Column(String, nullable=False)
    device_id = Column(String, index=True, nullable=False)
    action = Column(String, nullable=False)  # "Connected", "Disconnected", "Blocked"
