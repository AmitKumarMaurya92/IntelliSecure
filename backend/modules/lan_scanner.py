import os
import sys
import socket
import subprocess
import ipaddress
import concurrent.futures
import datetime
import re

# Resolve absolute path to logs directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DEFAULT_SUBNET    = "192.168.1.0/24"
MAX_WORKERS       = 64

def _ping_host(ip: str) -> bool:
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        return result.returncode == 0
    except Exception:
        return False

def _get_mac_address(ip: str) -> str:
    try:
        # ARP works on both Windows and Linux to get the MAC for a local IP
        if os.name == "nt":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            # Find the MAC pattern XX-XX-XX-XX-XX-XX
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", result.stdout)
            if match:
                return match.group(0).replace('-', ':').upper()
        else:
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", result.stdout)
            if match:
                return match.group(0).replace('-', ':').upper()
    except Exception:
        pass
    return "Unknown"

def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def scan_subnet(subnet: str = DEFAULT_SUBNET, max_workers: int = MAX_WORKERS) -> list[dict]:
    network     = ipaddress.ip_network(subnet, strict=False)
    all_hosts   = [str(ip) for ip in network.hosts()]
    active      = []
    scan_time   = datetime.datetime.utcnow().isoformat() + "Z"

    def check_host(ip: str) -> dict | None:
        if _ping_host(ip):
            hostname = _resolve_hostname(ip)
            mac = _get_mac_address(ip)
            return {
                "ip":        ip,
                "mac_address": mac,
                "hostname":  hostname if hostname != ip else "Unknown",
                "status":    "Online",
                "last_seen": scan_time
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in all_hosts}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                active.append(result)

    active.sort(key=lambda d: int(d["ip"].split(".")[-1]))
    return active

def get_known_ips_from_logs(db) -> set[str]:
    from ..models import NetworkLog
    try:
        rows = db.query(NetworkLog.source_ip).distinct().all()
        return {row.source_ip for row in rows}
    except Exception:
        return set()

def discover_devices(db=None, subnet: str = DEFAULT_SUBNET) -> dict:
    scan_start = datetime.datetime.utcnow()

    active_devices = scan_subnet(subnet)
    known_ips = get_known_ips_from_logs(db) if db else set()

    try:
        own_ip = socket.gethostbyname(socket.gethostname())
        known_ips.add(own_ip)
    except Exception:
        pass

    for device in active_devices:
        device["is_known"]    = device["ip"] in known_ips
        device["device_type"] = _guess_device_type(device["ip"], device["hostname"])

    known_count   = sum(1 for d in active_devices if d["is_known"])
    unknown_count = len(active_devices) - known_count
    scan_duration = int((datetime.datetime.utcnow() - scan_start).total_seconds() * 1000)

    return {
        "devices":        active_devices,
        "known_count":    known_count,
        "unknown_count":  unknown_count,
        "total_online":   len(active_devices),
        "subnet_scanned": subnet,
        "scan_timestamp": scan_start.isoformat() + "Z",
        "scan_duration_ms": scan_duration
    }

def _guess_device_type(ip: str, hostname: str) -> str:
    h = hostname.lower()
    if "router" in h or "gateway" in h or ip.endswith(".1"):
        return "Router/Gateway"
    if "printer" in h or "print" in h:
        return "Printer"
    if "cam" in h or "camera" in h:
        return "IP Camera"
    if "phone" in h or "mobile" in h:
        return "Mobile Device"
    if "server" in h or "srv" in h:
        return "Server"
    return "Workstation/Unknown"
