from __future__ import annotations

import ipaddress
import socket
from datetime import datetime
from typing import Any

try:
    import psutil
except Exception:
    psutil = None


SUSPICIOUS_PORTS = {
    4444: "Common reverse shell port",
    5555: "Common Android/debug/reverse shell port",
    6666: "Suspicious high-risk port",
    6667: "IRC botnet-related port",
    1337: "Common hacker-tool port",
    31337: "Classic backdoor port",
    23: "Telnet is insecure",
    2323: "IoT/Telnet-like suspicious port",
}


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _addr_parts(addr) -> tuple[str, int]:
    if not addr:
        return "", 0

    try:
        return str(addr.ip), int(addr.port)
    except Exception:
        pass

    try:
        return str(addr[0]), int(addr[1])
    except Exception:
        return str(addr), 0


def _is_public_ip(ip: str) -> bool:
    if not ip:
        return False

    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )
    except Exception:
        return False


def _process_info(pid: int | None) -> dict[str, str]:
    if psutil is None or pid is None:
        return {
            "process_name": "Unknown",
            "process_path": "",
            "process_cmdline": "",
        }

    try:
        proc = psutil.Process(pid)

        try:
            name = proc.name()
        except Exception:
            name = "Unknown"

        try:
            path = proc.exe()
        except Exception:
            path = ""

        try:
            cmdline = " ".join(proc.cmdline())
        except Exception:
            cmdline = ""

        return {
            "process_name": name or "Unknown",
            "process_path": path or "",
            "process_cmdline": cmdline or "",
        }

    except Exception:
        return {
            "process_name": "Unknown",
            "process_path": "",
            "process_cmdline": "",
        }


def _connection_risk(row: dict[str, Any]) -> tuple[int, str]:
    risk = 0
    reasons = []

    remote_ip = row.get("remote_address", "")
    remote_port = int(row.get("remote_port", 0) or 0)
    local_ip = row.get("local_address", "")
    local_port = int(row.get("local_port", 0) or 0)
    status = row.get("status", "")
    process_name = (row.get("process_name") or "").lower()

    if remote_port in SUSPICIOUS_PORTS:
        risk += 55
        reasons.append(SUSPICIOUS_PORTS[remote_port])

    if local_port in SUSPICIOUS_PORTS and status == "LISTEN":
        risk += 50
        reasons.append(f"Listening on suspicious port {local_port}")

    if _is_public_ip(remote_ip):
        risk += 10
        reasons.append("External public remote address")

    if local_ip in {"0.0.0.0", "::"} and status == "LISTEN":
        risk += 15
        reasons.append("Listening on all network interfaces")

    suspicious_processes = {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
    }

    if process_name in suspicious_processes and remote_ip:
        risk += 35
        reasons.append("Script or command interpreter has a network connection")

    risk = max(0, min(100, risk))

    if not reasons:
        reasons.append("No obvious suspicious network indicator")

    return risk, "; ".join(reasons)


def run_network_audit() -> dict[str, Any]:
    """
    Fast rule-based network audit.

    It does not capture packets.
    It only reads current OS network connections and process metadata.
    """
    if psutil is None:
        return {
            "ok": False,
            "created_at": _now(),
            "error": "psutil is not installed. Run: python -m pip install psutil",
            "connections": [],
            "findings": [],
            "summary": {},
        }

    connections = []
    findings = []

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        return {
            "ok": False,
            "created_at": _now(),
            "error": str(exc),
            "connections": [],
            "findings": [],
            "summary": {},
        }

    for conn in raw_connections:
        local_ip, local_port = _addr_parts(conn.laddr)
        remote_ip, remote_port = _addr_parts(conn.raddr)

        pid = conn.pid
        proc_info = _process_info(pid)

        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        status = conn.status if protocol == "TCP" else "NONE"

        row = {
            "pid": pid if pid is not None else "",
            "process_name": proc_info["process_name"],
            "process_path": proc_info["process_path"],
            "process_cmdline": proc_info["process_cmdline"],
            "protocol": protocol,
            "local_address": local_ip,
            "local_port": local_port,
            "remote_address": remote_ip,
            "remote_port": remote_port,
            "status": status,
        }

        risk, reason = _connection_risk(row)
        row["risk"] = risk
        row["reason"] = reason

        connections.append(row)

        if risk >= 40:
            findings.append(
                {
                    "time": _now(),
                    "severity": risk,
                    "title": "Suspicious network connection",
                    "pid": row["pid"],
                    "process_name": row["process_name"],
                    "local_address": row["local_address"],
                    "local_port": row["local_port"],
                    "remote_address": row["remote_address"],
                    "remote_port": row["remote_port"],
                    "reason": reason,
                }
            )

    connections.sort(key=lambda x: int(x.get("risk", 0)), reverse=True)

    summary = {
        "total_connections": len(connections),
        "external_connections": sum(1 for c in connections if _is_public_ip(c.get("remote_address", ""))),
        "listening_services": sum(1 for c in connections if c.get("status") == "LISTEN"),
        "suspicious_findings": len(findings),
        "highest_risk": max([int(c.get("risk", 0)) for c in connections] or [0]),
    }

    return {
        "ok": True,
        "created_at": _now(),
        "error": "",
        "connections": connections,
        "findings": findings,
        "summary": summary,
    }


def format_network_report_for_user(audit: dict[str, Any]) -> str:
    if not audit.get("ok"):
        return f"Network audit failed: {audit.get('error', 'Unknown error')}"

    summary = audit.get("summary", {})
    findings = audit.get("findings", [])

    lines = [
        "Network Audit Summary",
        "",
        f"Total connections: {summary.get('total_connections', 0)}",
        f"External connections: {summary.get('external_connections', 0)}",
        f"Listening services: {summary.get('listening_services', 0)}",
        f"Suspicious findings: {summary.get('suspicious_findings', 0)}",
        f"Highest risk: {summary.get('highest_risk', 0)}/100",
        "",
    ]

    if not findings:
        lines.append("No high-risk network connection was detected.")
    else:
        lines.append("Important findings:")
        lines.append("")

        for finding in findings[:10]:
            lines.append(
                f"- {finding.get('process_name')} "
                f"(PID {finding.get('pid')}) connected to "
                f"{finding.get('remote_address')}:{finding.get('remote_port')} "
                f"with risk {finding.get('severity')}/100."
            )
            lines.append(f"  Reason: {finding.get('reason')}")
            lines.append("")

    return "\n".join(lines)