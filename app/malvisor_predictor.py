from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

try:
    import joblib
except Exception:
    joblib = None

try:
    import numpy as np
except Exception:
    np = None

try:
    import pandas as pd
except Exception:
    pd = None

try:
    import pefile
except Exception:
    pefile = None

from .config import MALVISOR_MODEL_PATH, PE_EXTENSIONS

FEATURE_COLUMNS = [
    "num_imports",
    "section_count",
    "filesize",
    "entropy_mean",
    "entropy_max",
    "entropy_min",
    "string_count",
    "suspicious_string_count",
]

SUSPICIOUS_STRING_PATTERNS = [
    rb"http://", rb"https://", rb"powershell", rb"cmd.exe", rb"wscript",
    rb"cscript", rb"mshta", rb"reg add", rb"CurrentVersion\\Run",
    rb"CreateRemoteThread", rb"WriteProcessMemory", rb"VirtualAlloc",
    rb"URLDownloadToFile", rb"InternetOpen", rb"DownloadString",
    rb"FromBase64String", rb"ransom", rb"bitcoin", rb"monero", rb"xmrig",
]

TRUSTED_NAME_HINTS = {
    "python", "setup", "installer", "install", "update", "updater", "runtime",
    "redistributable", "vc_redist", "dotnet", "microsoft", "chrome", "firefox",
    "edge", "java", "jdk", "node", "vscode", "visualstudio",
}

_model = None
_model_error = ""


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return float(value)


def _extract_ascii_strings(data: bytes, min_length: int = 4) -> list[bytes]:
    pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
    return re.findall(pattern, data)


def extract_malvisor_features(file_path: str) -> dict[str, Any]:
    path = Path(file_path)
    features = {
        "num_imports": 0,
        "section_count": 0,
        "filesize": 0,
        "entropy_mean": 0.0,
        "entropy_max": 0.0,
        "entropy_min": 0.0,
        "string_count": 0,
        "suspicious_string_count": 0,
    }
    try:
        features["filesize"] = int(path.stat().st_size)
    except Exception:
        pass
    try:
        raw = path.read_bytes()
    except Exception:
        raw = b""

    strings = _extract_ascii_strings(raw)
    features["string_count"] = len(strings)
    lower_raw = raw.lower()
    features["suspicious_string_count"] = sum(1 for p in SUSPICIOUS_STRING_PATTERNS if p.lower() in lower_raw)

    if pefile is None:
        return features
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception:
        return features

    sections = getattr(pe, "sections", []) or []
    features["section_count"] = len(sections)
    entropies = []
    for section in sections:
        try:
            entropies.append(_entropy(section.get_data()))
        except Exception:
            pass
    if entropies:
        features["entropy_mean"] = float(sum(entropies) / len(entropies))
        features["entropy_max"] = float(max(entropies))
        features["entropy_min"] = float(min(entropies))

    num_imports = 0
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            num_imports += len(getattr(entry, "imports", []) or [])
    except Exception:
        pass
    features["num_imports"] = int(num_imports)
    return features


def malvisor_status() -> dict[str, Any]:
    return {
        "engine": "MalVisor LightGBM",
        "model_exists": MALVISOR_MODEL_PATH.exists(),
        "model_path": str(MALVISOR_MODEL_PATH),
        "joblib_available": joblib is not None,
        "pandas_available": pd is not None,
        "numpy_available": np is not None,
        "pefile_available": pefile is not None,
        "last_error": _model_error,
    }


def load_malvisor_model():
    global _model, _model_error
    if _model is not None:
        return _model
    if joblib is None:
        _model_error = "joblib is not installed"
        return None
    if pd is None:
        _model_error = "pandas is not installed"
        return None
    if not MALVISOR_MODEL_PATH.exists():
        _model_error = f"MalVisor model not found: {MALVISOR_MODEL_PATH}"
        return None
    try:
        _model = joblib.load(MALVISOR_MODEL_PATH)
        _model_error = ""
        return _model
    except Exception as exc:
        _model_error = str(exc)
        return None


def _predict_with_model(path: Path, features: dict[str, Any]) -> dict[str, Any]:
    model = load_malvisor_model()
    if model is None:
        return {
            "available": False,
            "label": "Model unavailable",
            "score": 0.0,
            "confidence": 0.0,
            "probabilities": {},
            "error": _model_error,
        }
    X = pd.DataFrame([[features[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    pred = model.predict(X)[0]
    label = str(pred)
    probabilities = {}
    confidence = 0.0
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        classes = [str(c) for c in getattr(model, "classes_", list(range(len(proba))))]
        probabilities = {cls: round(float(prob), 4) for cls, prob in zip(classes, proba)}
        confidence = max(probabilities.values()) if probabilities else 0.0

    lower_label = label.lower()
    if lower_label == "benign":
        score = 1.0 - confidence if confidence else 0.0
        shown = "Benign / low malware probability"
    elif confidence < 0.70:
        score = min(confidence, 0.49)
        shown = "Review recommended / uncertain AI result"
    elif confidence < 0.85:
        score = confidence
        shown = f"Possible {label}"
    else:
        score = confidence
        shown = label

    if any(hint in path.name.lower() for hint in TRUSTED_NAME_HINTS) and score < 0.75:
        score = min(score, 0.35)
        shown = "Likely legitimate installer / review optional"

    return {
        "available": True,
        "label": shown,
        "score": float(score),
        "confidence": float(confidence),
        "probabilities": probabilities,
        "error": "",
    }


def _fallback_pe_risk(path: Path, features: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons = []
    if features.get("entropy_max", 0) >= 7.2:
        score += 18
        reasons.append("High entropy section found")
    if features.get("suspicious_string_count", 0) >= 3:
        score += 18
        reasons.append("Suspicious strings found")
    if features.get("num_imports", 0) >= 300:
        score += 10
        reasons.append("Large import table")
    if any(hint in path.name.lower() for hint in TRUSTED_NAME_HINTS):
        score = max(0, score - 18)
        reasons.append("Trusted installer/runtime name hint")
    score = max(0, min(100, score))
    if score <= 20:
        label = "Low-risk PE"
    elif score <= 45:
        label = "Review recommended"
    else:
        label = "Suspicious PE"
    return {"score": score / 100.0, "label": label, "reasons": reasons}


def predict_malvisor_malware_type(file_path: str) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return _result(0.0, "Invalid file", 0.0, {}, "File does not exist")
    if path.suffix.lower() not in PE_EXTENSIONS:
        return _result(0.0, "Unsupported non-PE file", 0.0, {}, "")
    try:
        if path.read_bytes()[:2] != b"MZ":
            return _result(0.0, "Unsupported non-PE file", 0.0, {}, "")
    except Exception as exc:
        return _result(0.0, "Read error", 0.0, {}, str(exc))

    try:
        features = extract_malvisor_features(str(path))
        model_result = _predict_with_model(path, features)
        fallback = _fallback_pe_risk(path, features)
        if model_result["available"]:
            return _result(
                model_result["score"], model_result["label"], model_result["confidence"],
                model_result["probabilities"], model_result["error"], features, "MalVisor LightGBM"
            )
        return _result(
            fallback["score"], fallback["label"], 0.55, {}, model_result["error"], features,
            "Local PE Risk Fallback"
        )
    except Exception as exc:
        return _result(0.0, "ML error", 0.0, {}, str(exc))


def _result(score: float, label: str, confidence: float, probs: dict[str, float], error: str,
            features: dict[str, Any] | None = None, engine: str = "MalVisor LightGBM") -> dict[str, Any]:
    return {
        "ml_malware_score": round(float(score), 4),
        "ml_malware_type": label,
        "ml_confidence": round(float(confidence), 4),
        "ml_tag_scores": probs,
        "ml_error": error,
        "ml_engine": engine,
        "ml_features": features or {},
    }
