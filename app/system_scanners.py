from __future__ import annotations

import csv
import ctypes
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import psutil
except Exception:
    psutil = None

try:
    import winreg
except Exception:
    winreg = None

from .scanner import scan_path

SUSPICIOUS_CMD_PATTERNS = {
    "Encoded PowerShell": re.compile(r"powershell.*(-enc|-encodedcommand)", re.I),
    "PowerShell download": re.compile(r"powershell.*(downloadstring|invoke-webrequest|iwr|webclient)", re.I),
    "Certutil download/decode": re.compile(r"certutil.*(-urlcache|-decode|-decodehex|http)", re.I),
    "Regsvr32 remote script": re.compile(r"regsvr32.*(http|scrobj\.dll)", re.I),
    "MSHTA remote script": re.compile(r"mshta.*(http|javascript|vbscript)", re.I),
    "Credential tool keyword": re.compile(r"mimikatz|sekurlsa|procdump.*lsass|lsass", re.I),
}


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _event(source: str, category: str, severity: int, title: str, details: str, path: str = "") -> dict[str, Any]:
    return {
        "created_at": utc_now(),
        "source": source,
        "category": category,
        "severity": int(max(0, min(100, severity))),
        "title": title,
        "path": path,
        "details": details,
    }


def _match_patterns(command: str) -> list[str]:
    return [name for name, pattern in SUSPICIOUS_CMD_PATTERNS.items() if pattern.search(command or "")]


def get_removable_drives() -> list[str]:
    if platform.system().lower() != "windows":
        return []
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if bitmask & 1:
                root = f"{letter}:\\"
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
                if drive_type == 2:
                    drives.append(root)
            bitmask >>= 1
    except Exception:
        pass
    return drives


def run_usb_scan(quarantine: bool = False, manual_path: str = "") -> dict[str, Any]:
    targets = [manual_path] if manual_path else get_removable_drives()
    results = []
    events = []
    if not targets:
        return {"summary": "No removable drive was found.", "results": [], "events": []}
    for target in targets:
        try:
            scan_results = scan_path(target, quarantine=quarantine)
            results.extend(scan_results)
            risky = [r for r in scan_results if r.get("risk_score", 0) >= 55]
            if risky:
                events.append(_event("USB Scan", "USB", 75, "Risky files found on removable drive", f"{len(risky)} file(s) need review on {target}", target))
        except Exception as exc:
            events.append(_event("USB Scan", "USB", 0, "USB scan failed", str(exc), target))
    return {"summary": f"USB scan completed. Files scanned: {len(results)}", "results": results, "events": events}


def scan_startup_items() -> dict[str, Any]:
    events = []
    items = []
    folders = []
    if platform.system().lower() == "windows":
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        if appdata:
            folders.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if programdata:
            folders.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    for folder in folders:
        if folder.exists():
            for p in folder.glob("*"):
                items.append({"name": p.name, "path": str(p), "source": "Startup folder"})
                matches = _match_patterns(str(p))
                if matches:
                    events.append(_event("Startup Scan", "Startup", 70, "Suspicious startup file", ", ".join(matches), str(p)))
    if winreg and platform.system().lower() == "windows":
        run_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, key_path in run_paths:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        i += 1
                        items.append({"name": name, "path": str(value), "source": key_path})
                        matches = _match_patterns(str(value))
                        temp_or_user = any(x in str(value).lower() for x in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp"])
                        if matches or temp_or_user:
                            events.append(_event("Startup Scan", "Startup", 60 + 10 * bool(matches), "Startup item needs review", "; ".join(matches) or "Runs from user/temp location", str(value)))
            except Exception:
                pass
    return {"items": items, "events": events, "summary": f"Startup scan completed. Items checked: {len(items)}"}


def scan_scheduled_tasks() -> dict[str, Any]:
    events = []
    tasks = []
    if platform.system().lower() != "windows":
        return {"tasks": [], "events": [_event("Scheduled Tasks", "Scheduled Tasks", 0, "Scheduled tasks scan unavailable", "This scan is Windows-only.")], "summary": "Scheduled tasks scan unavailable on this OS."}
    try:
        proc = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/v"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=45)
        if proc.returncode != 0:
            return {"tasks": [], "events": [_event("Scheduled Tasks", "Scheduled Tasks", 0, "schtasks failed", proc.stderr[:1000])], "summary": "Scheduled tasks query failed."}
        reader = csv.DictReader(proc.stdout.splitlines())
        for row in reader:
            name = row.get("TaskName", "")
            action = row.get("Task To Run", "") or row.get("Task To Run", "")
            tasks.append({"name": name, "action": action, "status": row.get("Status", "")})
            matches = _match_patterns(action)
            temp_path = any(x in action.lower() for x in ["\\temp\\", "\\downloads\\", "appdata\\local\\temp"])
            if matches or temp_path:
                events.append(_event("Scheduled Tasks", "Scheduled Tasks", 70, "Scheduled task needs review", f"Task={name}; Action={action}; Reasons={', '.join(matches) or 'user/temp path'}", action))
    except Exception as exc:
        events.append(_event("Scheduled Tasks", "Scheduled Tasks", 0, "Scheduled task scan failed", str(exc)))
    return {"tasks": tasks, "events": events, "summary": f"Scheduled tasks checked: {len(tasks)}"}


def scan_process_behavior() -> dict[str, Any]:
    if psutil is None:
        return {"processes": [], "events": [_event("Process Behavior", "Processes", 0, "Process scanner unavailable", "Install psutil.")], "summary": "psutil unavailable."}
    events = []
    processes = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            cmd = " ".join(info.get("cmdline") or [])
            exe = info.get("exe") or ""
            name = info.get("name") or ""
            processes.append({"pid": info.get("pid"), "name": name, "exe": exe, "cmdline": cmd})
            matches = _match_patterns(cmd)
            if matches:
                events.append(_event("Process Behavior", "Processes", 75, "Suspicious process command line", f"PID={info.get('pid')}; {', '.join(matches)}; Command={cmd}", exe))
        except Exception:
            pass
    return {"processes": processes, "events": events, "summary": f"Processes checked: {len(processes)}"}


def scan_memory_processes() -> dict[str, Any]:
    if psutil is None:
        return {"processes": [], "events": [_event("Memory Scan", "Memory", 0, "Memory scanner unavailable", "Install psutil.")], "summary": "psutil unavailable."}
    events = []
    rows = []
    try:
        total_mem = psutil.virtual_memory().total
    except Exception:
        total_mem = 1
    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cmdline"]):
        try:
            info = proc.info
            rss = int(info.get("memory_info").rss) if info.get("memory_info") else 0
            mb = rss / (1024 * 1024)
            percent = 100 * rss / max(1, total_mem)
            exe = info.get("exe") or ""
            cmd = " ".join(info.get("cmdline") or [])
            rows.append({"pid": info.get("pid"), "name": info.get("name"), "memory_mb": round(mb, 1), "exe": exe})
            risky_location = any(x in exe.lower() for x in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp"])
            if mb > 1200 and risky_location:
                events.append(_event("Memory Scan", "Memory", 65, "High-memory process from user/temp location", f"PID={info.get('pid')}; Memory={mb:.1f} MB; Command={cmd}", exe))
        except Exception:
            pass
    rows.sort(key=lambda x: x.get("memory_mb", 0), reverse=True)
    return {"processes": rows[:200], "events": events, "summary": f"Memory/process scan completed. Processes checked: {len(rows)}"}
