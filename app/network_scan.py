from __future__ import annotations

from datetime import datetime
import ipaddress
from typing import Any

try:
    import psutil
except Exception:
    psutil = None

SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 1337, 31337, 9001, 9050}
COMMON_SAFE_PORTS = {53, 80, 123, 443, 445, 3389, 5353, 1900}


def _is_private_or_local(host: str) -> bool:
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except Exception:
        return False


def network_status() -> dict[str, Any]:
    return {"psutil_available": psutil is not None, "engine": "Endpoint Network Audit"}


def run_network_audit() -> dict[str, Any]:
    if psutil is None:
        return {"available": False, "connections": [], "findings": [{"severity": 0, "title": "Network scanner unavailable", "details": "Install psutil."}]}
    connections = []
    findings = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr_ip = conn.raddr.ip if conn.raddr else ""
            raddr_port = conn.raddr.port if conn.raddr else ""
            raddr = f"{raddr_ip}:{raddr_port}" if conn.raddr else ""
            proc_name = ""
            proc_path = ""
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                    proc_path = p.exe()
                except Exception:
                    pass
            item = {
                "protocol": "TCP" if conn.type == 1 else "UDP",
                "status": conn.status,
                "pid": conn.pid or "",
                "process": proc_name,
                "path": proc_path,
                "local": laddr,
                "remote": raddr,
                "remote_ip": raddr_ip,
                "remote_port": raddr_port,
            }
            connections.append(item)

            severity = 0
            reasons = []
            try:
                port_int = int(raddr_port or 0)
            except Exception:
                port_int = 0
            if port_int in SUSPICIOUS_PORTS:
                severity += 65
                reasons.append(f"connection to uncommon high-risk port {port_int}")
            if raddr_ip and not _is_private_or_local(raddr_ip) and conn.status == "ESTABLISHED":
                severity += 15
                reasons.append("active external connection")
            if conn.status == "LISTEN" and conn.laddr and conn.laddr.port not in COMMON_SAFE_PORTS:
                severity += 20
                reasons.append(f"listening on port {conn.laddr.port}")
            if severity > 0:
                findings.append({
                    "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "source": "Network",
                    "category": "Network",
                    "severity": min(100, severity),
                    "title": "Network connection to review",
                    "path": proc_path,
                    "details": f"{proc_name or 'Unknown process'} {laddr} -> {raddr}. Reasons: {', '.join(reasons)}",
                })
    except Exception as exc:
        findings.append({"severity": 0, "title": "Network audit failed", "details": str(exc)})
    return {"available": True, "connections": connections, "findings": findings}
