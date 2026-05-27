from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
from pathlib import Path
from typing import Any, Iterator

from .config import (
    BASE_DIR,
    IGNORED_SCAN_DIRS,
    KNOWN_BAD_HASHES,
    PE_EXTENSIONS,
    QUARANTINE_DIR,
    RULES_DIR,
    SCRIPT_EXTENSIONS,
    RISK_CLEAN_MAX,
    RISK_REVIEW_MAX,
    RISK_MALICIOUS_MAX,
)
from .malvisor_predictor import predict_malvisor_malware_type

try:
    import yara
except Exception:
    yara = None

try:
    import pefile
except Exception:
    pefile = None

SCRIPT_PATTERNS = {
    "Encoded PowerShell command": re.compile(r"EncodedCommand|-enc\b", re.I),
    "PowerShell web download": re.compile(r"Invoke-WebRequest|DownloadString|WebClient|iwr\b", re.I),
    "Base64 decode": re.compile(r"FromBase64String|base64", re.I),
    "Registry persistence command": re.compile(r"reg\s+add|CurrentVersion\\Run", re.I),
    "Scheduled task creation": re.compile(r"schtasks\b", re.I),
    "Hidden script execution": re.compile(r"WindowStyle\s+Hidden|wscript\.shell", re.I),
}

SUSPICIOUS_IMPORT_WEIGHTS = {
    "CreateRemoteThread": 28,
    "WriteProcessMemory": 28,
    "VirtualAllocEx": 18,
    "VirtualProtectEx": 14,
    "VirtualAlloc": 5,
    "VirtualProtect": 5,
    "URLDownloadToFileA": 22,
    "URLDownloadToFileW": 22,
    "InternetOpenA": 10,
    "InternetOpenW": 10,
    "WinHttpSendRequest": 15,
    "RegSetValueExA": 15,
    "RegSetValueExW": 15,
    "CreateServiceA": 20,
    "CreateServiceW": 20,
    "CryptEncrypt": 12,
    "BCryptEncrypt": 12,
    "IsDebuggerPresent": 10,
    "CheckRemoteDebuggerPresent": 12,
    "CreateProcessA": 6,
    "CreateProcessW": 6,
}

TRUSTED_NAME_HINTS = {
    "python", "setup", "installer", "install", "update", "updater", "runtime",
    "redistributable", "microsoft", "chrome", "firefox", "edge", "java", "node", "vscode",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def add_detection(detections: list[dict[str, Any]], engine: str, name: str, severity: int,
                  details: str, category: str = "File") -> None:
    detections.append({
        "engine": engine,
        "name": name,
        "severity": int(max(0, min(100, severity))),
        "category": category,
        "details": details,
    })


def load_yara_rules():
    if yara is None:
        return None
    rule_files = list(Path(RULES_DIR).glob("*.yar")) + list(Path(RULES_DIR).glob("*.yara"))
    if not rule_files:
        return None
    try:
        return yara.compile(filepaths={str(i): str(p) for i, p in enumerate(rule_files)})
    except Exception:
        return None


def _is_project_self_file(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(BASE_DIR.resolve())
    except Exception:
        return False
    parts = {p.lower() for p in relative.parts}
    return "app" in parts or "rules" in parts


def yara_scan(path: Path, detections: list[dict[str, Any]]) -> None:
    rules = load_yara_rules()
    if rules is None:
        return
    try:
        matches = rules.match(str(path))
    except Exception as exc:
        add_detection(detections, "YARA", "YARA scan error", 5, str(exc), "Scanner")
        return
    for match in matches:
        severity = 35
        description = "YARA rule matched"
        try:
            severity = int(match.meta.get("severity", severity))
            description = match.meta.get("description", description)
        except Exception:
            pass
        if _is_project_self_file(path):
            severity = min(severity, 10)
            description += " (low confidence because this file is part of the scanner project)"
        add_detection(detections, "YARA", match.rule, severity, description, "Signature")


def hash_scan(digest: str, detections: list[dict[str, Any]]) -> None:
    if digest in KNOWN_BAD_HASHES:
        add_detection(detections, "Hash", KNOWN_BAD_HASHES[digest], 90, f"Known bad/test SHA-256 matched: {digest}", "Reputation")


def script_scan(path: Path, detections: list[dict[str, Any]]) -> None:
    if path.suffix.lower() not in SCRIPT_EXTENSIONS:
        return
    try:
        text = path.read_text(errors="ignore")
    except Exception as exc:
        add_detection(detections, "Script", "Script read error", 5, str(exc), "Script")
        return
    matched = [name for name, pattern in SCRIPT_PATTERNS.items() if pattern.search(text)]
    if matched:
        severity = min(70, 15 + len(matched) * 12)
        if _is_project_self_file(path):
            severity = min(severity, 12)
        add_detection(detections, "Script", "Suspicious script content", severity, ", ".join(matched), "Script")


def pe_scan(path: Path, detections: list[dict[str, Any]]) -> None:
    if path.suffix.lower() not in PE_EXTENSIONS:
        return
    if pefile is None:
        add_detection(detections, "PE", "PE parser unavailable", 5, "Install pefile for PE analysis", "PE")
        return
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        add_detection(detections, "PE", "Invalid or unreadable PE", 10, str(exc), "PE")
        return

    imports = set()
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode(errors="ignore"))
    except Exception:
        pass
    found = sorted(i for i in imports if i in SUSPICIOUS_IMPORT_WEIGHTS)
    if found:
        severity = min(70, sum(SUSPICIOUS_IMPORT_WEIGHTS.get(i, 0) for i in found) // 2)
        # Generic APIs alone are weak signals.
        if set(found) <= {"VirtualAlloc", "VirtualProtect", "CreateProcessA", "CreateProcessW"}:
            severity = min(severity, 15)
        add_detection(detections, "PE", "Suspicious Windows API imports", severity, ", ".join(found[:20]), "PE")

    high_entropy = []
    rwx_sections = []
    for section in getattr(pe, "sections", []) or []:
        try:
            name = section.Name.decode(errors="ignore").strip("\x00") or "section"
            ent = entropy(section.get_data())
            if ent >= 7.2:
                high_entropy.append(f"{name} ({ent:.2f})")
            executable = bool(section.Characteristics & 0x20000000)
            writable = bool(section.Characteristics & 0x80000000)
            if executable and writable:
                rwx_sections.append(name)
        except Exception:
            pass
    if high_entropy:
        severity = min(50, 12 + len(high_entropy) * 8)
        add_detection(detections, "PE", "High entropy section", severity, ", ".join(high_entropy[:8]), "PE")
    if rwx_sections:
        add_detection(detections, "PE", "Writable and executable section", 45, ", ".join(rwx_sections[:8]), "PE")


def generic_entropy_scan(path: Path, detections: list[dict[str, Any]]) -> None:
    try:
        size = path.stat().st_size
        if size == 0:
            return
        with path.open("rb") as f:
            sample = f.read(2 * 1024 * 1024)
        ent = entropy(sample)
        if ent >= 7.7 and path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".zip", ".rar", ".7z", ".mp4"}:
            add_detection(detections, "Entropy", "Very high file entropy", 20, f"Entropy {ent:.2f}. Could be compressed or packed.", "File")
    except Exception:
        pass


def classify_risk(score: int) -> tuple[str, str]:
    score = int(max(0, min(100, score)))
    if score <= RISK_CLEAN_MAX:
        return "Clean", "Well trusted" if score <= 10 else f"Trusted ({score}/100)"
    if score <= RISK_REVIEW_MAX:
        return "Review needed", f"Review needed ({score}/100)"
    if score <= RISK_MALICIOUS_MAX:
        return "Malicious", f"Malicious risk ({score}/100)"
    return "High risk", f"High risk ({score}/100)"


def quarantine_file(path: Path, digest: str) -> str:
    QUARANTINE_DIR.mkdir(exist_ok=True)
    target = QUARANTINE_DIR / f"{digest}_{path.name}"
    if target.exists():
        target = QUARANTINE_DIR / f"{digest}_{os.getpid()}_{path.name}"
    shutil.move(str(path), str(target))
    meta = target.with_suffix(target.suffix + ".meta.txt")
    meta.write_text(f"original_path={path}\nsha256={digest}\n", encoding="utf-8")
    return str(target)


def scan_file(file_path: str, quarantine: bool = False) -> dict[str, Any]:
    path = Path(file_path)
    detections: list[dict[str, Any]] = []
    result = {
        "path": str(path),
        "sha256": "",
        "verdict": "Error",
        "risk_score": 0,
        "trust_label": "Scan error",
        "detections": detections,
        "model_engine": "",
        "model_type": "",
        "model_confidence": 0.0,
        "quarantined": False,
        "quarantine_path": "",
    }
    if not path.exists() or not path.is_file():
        add_detection(detections, "Scanner", "File unavailable", 0, "File does not exist or is not a regular file", "Error")
        return result
    try:
        digest = sha256_file(path)
        result["sha256"] = digest
        hash_scan(digest, detections)
        yara_scan(path, detections)
        script_scan(path, detections)
        pe_scan(path, detections)
        generic_entropy_scan(path, detections)

        ml = predict_malvisor_malware_type(str(path))
        result["model_engine"] = ml.get("ml_engine", "")
        result["model_type"] = ml.get("ml_malware_type", "")
        result["model_confidence"] = float(ml.get("ml_confidence", 0.0) or 0.0)
        model_score = float(ml.get("ml_malware_score", 0.0) or 0.0) * 100.0
        ml_error = ml.get("ml_error", "")
        if ml_error and "Model not found" not in ml_error:
            add_detection(detections, "AI Model", "AI model warning", 0, ml_error, "AI")
        if model_score >= 70:
            add_detection(detections, result["model_engine"] or "AI Model", result["model_type"], int(model_score), f"Model confidence {result['model_confidence']:.1%}", "AI")
        elif model_score >= 40:
            add_detection(detections, result["model_engine"] or "AI Model", "AI review recommendation", int(model_score), result["model_type"], "AI")

        classic_score = max([int(d.get("severity", 0)) for d in detections] + [0])
        combined_score = max(classic_score, int(round(model_score)))
        # Reduce false positives for trusted installer names if no strong detection.
        if any(hint in path.name.lower() for hint in TRUSTED_NAME_HINTS) and combined_score < 75:
            combined_score = min(combined_score, 35)
        verdict, label = classify_risk(combined_score)
        result["risk_score"] = combined_score
        result["verdict"] = verdict
        result["trust_label"] = label
        if quarantine and combined_score >= 60:
            try:
                result["quarantine_path"] = quarantine_file(path, digest)
                result["quarantined"] = True
            except Exception as exc:
                add_detection(detections, "Quarantine", "Quarantine failed", 5, str(exc), "Action")
        return result
    except Exception as exc:
        add_detection(detections, "Scanner", "Unhandled scan error", 0, str(exc), "Error")
        return result


def collect_scan_targets(path_text: str) -> list[Path]:
    target = Path(path_text).resolve()
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        return []
    files: list[Path] = []
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d.lower() not in IGNORED_SCAN_DIRS]
        for filename in filenames:
            p = Path(root) / filename
            try:
                if p.is_file():
                    files.append(p)
            except Exception:
                pass
    return files


def scan_path(path_text: str, quarantine: bool = False) -> list[dict[str, Any]]:
    return [scan_file(str(p), quarantine=quarantine) for p in collect_scan_targets(path_text)]
