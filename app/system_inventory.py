from __future__ import annotations

import csv
import os
import platform
import subprocess
from io import StringIO
from pathlib import Path
from typing import Any

try:
    import psutil
except Exception:
    psutil = None


SKIP_DIRS = {
    ".git", ".idea", ".vscode", ".venv", "venv", "env",
    "__pycache__", "node_modules", "reports", "quarantine",
}


def _row(
    item_type: str,
    name: str,
    pid: str | int = "",
    path: str = "",
    status: str = "Checked",
    risk: int = 0,
    details: str = "",
    source: str = "SystemInventory",
) -> dict[str, Any]:
    return {
        "status": status,
        "type": item_type,
        "name": name or "",
        "pid": str(pid or ""),
        "path": path or "",
        "risk": int(risk or 0),
        "details": details or "",
        "source": source,
    }


def _safe_join_cmdline(cmdline: Any) -> str:
    if isinstance(cmdline, (list, tuple)):
        return " ".join(str(x) for x in cmdline)
    return str(cmdline or "")


def collect_process_items(limit: int = 2000) -> list[dict[str, Any]]:
    rows = []

    if psutil is None:
        return [_row("Process", "Process inventory unavailable", status="Unavailable", details="psutil is not installed.")]

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid"]):
        if len(rows) >= limit:
            break

        try:
            info = proc.info
            cmdline = _safe_join_cmdline(info.get("cmdline"))
            details = f"User={info.get('username') or ''}; PPID={info.get('ppid') or ''}"

            if cmdline:
                details += f"; Command={cmdline[:500]}"

            rows.append(
                _row(
                    "Process",
                    info.get("name") or f"PID {info.get('pid')}",
                    pid=info.get("pid"),
                    path=info.get("exe") or "",
                    details=details,
                    source="ProcessInventory",
                )
            )
        except Exception:
            continue

    return rows


def collect_memory_process_items(limit: int = 2000) -> list[dict[str, Any]]:
    rows = []

    if psutil is None:
        return [_row("Memory process", "Memory inventory unavailable", status="Unavailable", details="psutil is not installed.")]

    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cpu_percent", "username"]):
        if len(rows) >= limit:
            break

        try:
            info = proc.info
            mem = info.get("memory_info")
            rss = getattr(mem, "rss", 0) if mem else 0
            rss_mb = rss / (1024 * 1024)

            details = (
                f"Memory={rss_mb:.1f} MB; "
                f"CPU={info.get('cpu_percent', 0)}%; "
                f"User={info.get('username') or ''}"
            )

            rows.append(
                _row(
                    "Memory process",
                    info.get("name") or f"PID {info.get('pid')}",
                    pid=info.get("pid"),
                    path=info.get("exe") or "",
                    details=details,
                    source="MemoryInventory",
                )
            )
        except Exception:
            continue

    return rows


def collect_startup_items() -> list[dict[str, Any]]:
    rows = []

    startup_folders = [
        Path(os.getenv("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.getenv("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]

    for folder in startup_folders:
        try:
            if folder.exists():
                for item in folder.iterdir():
                    rows.append(
                        _row(
                            "Startup item",
                            item.name,
                            path=str(item),
                            details=f"Startup folder item: {folder}",
                            source="StartupInventory",
                        )
                    )
        except Exception:
            pass

    if platform.system().lower() == "windows":
        try:
            import winreg

            keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            ]

            for root, key_path, label in keys:
                try:
                    with winreg.OpenKey(root, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                rows.append(
                                    _row(
                                        "Startup registry",
                                        str(name),
                                        path=str(value),
                                        details=label,
                                        source="StartupInventory",
                                    )
                                )
                                i += 1
                            except OSError:
                                break
                except Exception:
                    continue
        except Exception:
            pass

    if not rows:
        rows.append(
            _row(
                "Startup item",
                "No startup entries collected",
                details="No startup folder or registry startup item was collected.",
                source="StartupInventory",
            )
        )

    return rows


def collect_scheduled_task_items(limit: int = 2000) -> list[dict[str, Any]]:
    rows = []

    if platform.system().lower() != "windows":
        return [_row("Scheduled task", "Scheduled task inventory unavailable", status="Unavailable", details="Windows only.")]

    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=40,
            check=False,
        )

        if proc.returncode != 0:
            return [
                _row(
                    "Scheduled task",
                    "Could not read scheduled tasks",
                    status="Unavailable",
                    details=(proc.stderr or proc.stdout or "")[:1000],
                    source="TaskInventory",
                )
            ]

        reader = csv.DictReader(StringIO(proc.stdout))

        for task in reader:
            if len(rows) >= limit:
                break

            name = task.get("TaskName") or task.get("Task To Run") or "Scheduled task"
            command = task.get("Task To Run") or ""
            status = task.get("Status") or ""
            author = task.get("Author") or ""

            rows.append(
                _row(
                    "Scheduled task",
                    name,
                    path=command,
                    details=f"Status={status}; Author={author}",
                    source="TaskInventory",
                )
            )

    except Exception as exc:
        rows.append(
            _row(
                "Scheduled task",
                "Scheduled task inventory failed",
                status="Unavailable",
                details=str(exc),
                source="TaskInventory",
            )
        )

    return rows


def collect_usb_file_items(manual_path: str = "", limit: int = 3000) -> list[dict[str, Any]]:
    rows = []
    targets = []

    if manual_path:
        p = Path(manual_path)
        if p.exists():
            targets.append(p)

    if not targets and psutil is not None:
        for part in psutil.disk_partitions(all=False):
            try:
                if "removable" in (part.opts or "").lower():
                    targets.append(Path(part.mountpoint))
            except Exception:
                pass

    if not targets:
        return [
            _row(
                "USB file",
                "No USB/manual folder selected",
                details="No removable drive was found. Use manual folder selection if needed.",
                source="USBInventory",
            )
        ]

    for target in targets:
        try:
            if target.is_file():
                rows.append(
                    _row(
                        "USB file",
                        target.name,
                        path=str(target),
                        details=f"Size={target.stat().st_size} bytes",
                        source="USBInventory",
                    )
                )
                continue

            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

                for name in files:
                    if len(rows) >= limit:
                        return rows

                    fp = Path(root) / name

                    try:
                        size = fp.stat().st_size
                    except Exception:
                        size = 0

                    rows.append(
                        _row(
                            "USB file",
                            name,
                            path=str(fp),
                            details=f"Size={size} bytes",
                            source="USBInventory",
                        )
                    )
        except Exception:
            continue

    return rows


def collect_system_checked_items(action: str, manual_path: str = "") -> list[dict[str, Any]]:
    action = (action or "").lower()

    if action == "usb":
        return collect_usb_file_items(manual_path)

    if action == "startup":
        return collect_startup_items()

    if action == "tasks":
        return collect_scheduled_task_items()

    if action == "process":
        return collect_process_items()

    if action == "memory":
        return collect_memory_process_items()

    return []
