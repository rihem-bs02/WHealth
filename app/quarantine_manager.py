from __future__ import annotations

from pathlib import Path
from typing import Any
import shutil

from .config import QUARANTINE_DIR


def list_quarantine_items() -> list[dict[str, Any]]:
    QUARANTINE_DIR.mkdir(exist_ok=True)
    items = []
    for path in QUARANTINE_DIR.iterdir():
        if path.name.endswith(".meta.txt") or path.is_dir():
            continue
        original = ""
        digest = ""
        meta = path.with_suffix(path.suffix + ".meta.txt")
        if meta.exists():
            for line in meta.read_text(errors="ignore").splitlines():
                if line.startswith("original_path="):
                    original = line.split("=", 1)[1]
                elif line.startswith("sha256="):
                    digest = line.split("=", 1)[1]
        try:
            size = path.stat().st_size
            modified = path.stat().st_mtime
        except Exception:
            size = 0
            modified = 0
        items.append({"name": path.name, "quarantine_path": str(path), "original_path": original, "sha256": digest, "size": size, "modified": modified})
    return sorted(items, key=lambda x: x.get("modified", 0), reverse=True)


def restore_quarantine_item(quarantine_path: str) -> str:
    path = Path(quarantine_path)
    if not path.exists():
        raise FileNotFoundError("Quarantined file not found")
    meta = path.with_suffix(path.suffix + ".meta.txt")
    original = ""
    if meta.exists():
        for line in meta.read_text(errors="ignore").splitlines():
            if line.startswith("original_path="):
                original = line.split("=", 1)[1]
                break
    if not original:
        raise ValueError("Original path is unknown")
    target = Path(original)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError("Original path already exists; restore manually to avoid overwrite")
    shutil.move(str(path), str(target))
    if meta.exists():
        meta.unlink(missing_ok=True)
    return str(target)


def delete_quarantine_item(quarantine_path: str) -> None:
    path = Path(quarantine_path)
    meta = path.with_suffix(path.suffix + ".meta.txt")
    path.unlink(missing_ok=True)
    meta.unlink(missing_ok=True)
