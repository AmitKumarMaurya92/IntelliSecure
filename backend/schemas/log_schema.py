from pydantic import BaseModel
from typing import Optional

class LoginLogCreate(BaseModel):
    username: str
    ip_address: str
    status: str
    timestamp: Optional[str] = None

class NetworkLogCreate(BaseModel):
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    action: str
    timestamp: Optional[str] = None

class FileAccessLogCreate(BaseModel):
    username: str
    file_path: str
    access_type: str
    status: str
    timestamp: Optional[str] = None

class MalwareLogCreate(BaseModel):
    file_name: str
    file_path: str
    hash: str
    signature: str
    action: str
    timestamp: Optional[str] = None

class USBLogCreate(BaseModel):
    username: str
    device_name: str
    device_id: str
    action: str
    timestamp: Optional[str] = None
