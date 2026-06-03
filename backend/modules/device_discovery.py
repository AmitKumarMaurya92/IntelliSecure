"""
LAN Device Discovery Module
==============================
Discovers active devices on the local network using ICMP ping sweep.
Resolves hostnames and attempts to identify device types.

Strategy:
  1. Ping sweep the /24 subnet (192.168.1.0/24 by default)
  2. Resolve hostnames via reverse DNS
  3. Cross-reference with network_logs to flag known vs unknown devices
  4. Mark devices not seen in network_logs as "Unknown"

Note: On Windows, uses subprocess ping. No admin rights required for ICMP.

Author: IntelliSecure Team
"""

import os
import sys
import socket
import subprocess
import ipaddress
import concurrent.futures
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# â”€â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DEFAULT_SUBNET    = "192.168.1.0/24"
PING_TIMEOUT_SEC  = 0.5           # Timeout per ping
MAX_WORKERS       = 64            # Concurrent threads for ping sweep
PING_COUNT        = 1             # Number of ICMP packets per host


def _ping_host(ip: str) -> bool:
    """
    Ping a single host. Returns True if host responds, False otherwise.
    Compatible with Windows (uses -n) and Linux/Mac (uses -c).
    """
    try:
        if os.name == "nt":  # Windows
            result = subprocess.run(
                ["ping", "-n", str(PING_COUNT), "-w", "500", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        else:  # Linux / macOS
            result = subprocess.run(
                ["ping", "-c", str(PING_COUNT), "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS resolution. Returns IP if resolution fails."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def scan_subnet(subnet: str = DEFAULT_SUBNET, max_workers: int = MAX_WORKERS) -> list[dict]:
    """
    Perform a parallel ping sweep of the given subnet.

    Args:
        subnet:     CIDR notation (e.g., "192.168.1.0/24")
        max_workers: Number of concurrent ping threads

    Returns:
        List of dicts for each active host:
        { ip, hostname, status, last_seen }
    """
    network     = ipaddress.ip_network(subnet, strict=False)
    all_hosts   = [str(ip) for ip in network.hosts()]
    active      = []
    scan_time   = datetime.datetime.utcnow().isoformat() + "Z"

    def check_host(ip: str) -> dict | None:
        if _ping_host(ip):
            hostname = _resolve_hostname(ip)
            return {
                "ip":        ip,
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

    # Sort by last octet of IP
    active.sort(key=lambda d: int(d["ip"].split(".")[-1]))
    return active


def get_known_ips_from_logs(db) -> set[str]:
    """Query network_logs to get set of IPs that have been seen before."""
    from ..models import NetworkLog
    try:
        rows = db.query(NetworkLog.source_ip).distinct().all()
        return {row.source_ip for row in rows}
    except Exception:
        return set()


def discover_devices(db=None, subnet: str = DEFAULT_SUBNET) -> dict:
    """
    Main entry point: scan LAN, classify devices, return full inventory.

    Args:
        db:     SQLAlchemy DB session (optional â€” used for known IP lookup)
        subnet: Subnet to scan

    Returns:
        {
            devices:         [...],
            known_count:     int,
            unknown_count:   int,
            total_online:    int,
            subnet_scanned:  str,
            scan_timestamp:  str
        }
    """
    scan_start = datetime.datetime.utcnow()

    # Run ping sweep
    active_devices = scan_subnet(subnet)

    # Get known IPs from DB (if DB session provided)
    known_ips = get_known_ips_from_logs(db) if db else set()

    # Also add our own machine's IP as "known"
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
        known_ips.add(own_ip)
    except Exception:
        pass

    # Classify devices
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
    """Heuristic device type guessing from IP/hostname patterns."""
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
