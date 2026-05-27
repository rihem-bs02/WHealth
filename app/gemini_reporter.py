from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.2:1b")


def _post_json(url: str, payload: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def _get_json(url: str, timeout: int = 10) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def _ollama_binary_exists() -> bool:
    try:
        completed = subprocess.run(
            ["ollama", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return completed.returncode == 0
    except Exception:
        return False


def _start_ollama_server_if_needed() -> None:
    try:
        _get_json(f"{OLLAMA_HOST}/api/tags", timeout=3)
        return
    except Exception:
        pass

    try:
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW

        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

        for _ in range(20):
            try:
                _get_json(f"{OLLAMA_HOST}/api/tags", timeout=3)
                return
            except Exception:
                time.sleep(0.5)

    except Exception:
        return


def _installed_ollama_models() -> set[str]:
    try:
        data = _get_json(f"{OLLAMA_HOST}/api/tags", timeout=10)
        models = data.get("models", []) or []

        names = set()
        for model in models:
            name = model.get("name")
            if name:
                names.add(name)

        return names

    except Exception:
        return set()


def _pull_model(model: str) -> tuple[bool, str]:
    """
    Pulls the Ollama model using the Ollama CLI.
    Returns (success, message).
    """
    if not _ollama_binary_exists():
        return (
            False,
            "Ollama is not installed. Install it with: winget install Ollama.Ollama",
        )

    try:
        completed = subprocess.run(
            ["ollama", "pull", model],
            capture_output=True,
            text=True,
            timeout=1800,
        )

        if completed.returncode == 0:
            return True, f"Model {model} installed successfully."

        error = completed.stderr.strip() or completed.stdout.strip()
        return False, f"Could not pull model {model}: {error}"

    except subprocess.TimeoutExpired:
        return False, f"Timeout while pulling model {model}."

    except Exception as exc:
        return False, f"Could not pull model {model}: {exc}"


def ensure_ollama_model() -> tuple[bool, str, str]:
    """
    Ensures Ollama is installed, server is running, and a usable model exists.
    Returns (ok, model_name, message).
    """
    if not _ollama_binary_exists():
        return (
            False,
            "",
            "Ollama is not installed. Run: winget install Ollama.Ollama",
        )

    _start_ollama_server_if_needed()

    installed = _installed_ollama_models()

    if OLLAMA_MODEL in installed:
        return True, OLLAMA_MODEL, f"Ollama model available: {OLLAMA_MODEL}"

    ok, msg = _pull_model(OLLAMA_MODEL)

    if ok:
        return True, OLLAMA_MODEL, msg

    installed = _installed_ollama_models()

    if OLLAMA_FALLBACK_MODEL in installed:
        return True, OLLAMA_FALLBACK_MODEL, (
            f"Main model unavailable, using fallback model: {OLLAMA_FALLBACK_MODEL}"
        )

    ok2, msg2 = _pull_model(OLLAMA_FALLBACK_MODEL)

    if ok2:
        return True, OLLAMA_FALLBACK_MODEL, msg2

    return False, "", msg + "\n" + msg2


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _summarize_scan_locally(results: list[dict[str, Any]]) -> str:
    total = len(results)
    clean = sum(1 for r in results if r.get("verdict") == "Clean")
    review = sum(1 for r in results if r.get("verdict") == "Review needed")
    high = sum(1 for r in results if r.get("verdict") in {"Malicious", "High risk", "High-risk malware"})
    errors = sum(1 for r in results if r.get("verdict") == "Error")
    quarantined = sum(1 for r in results if r.get("quarantined"))

    lines = [
        "AI Security Summary",
        "",
        f"The scan analyzed {total} file(s).",
        f"Trusted files: {clean}",
        f"Files needing review: {review}",
        f"High-risk files: {high}",
        f"Errors or unknown results: {errors}",
        f"Quarantined files: {quarantined}",
        "",
    ]

    important = sorted(
        results,
        key=lambda r: _safe_int(r.get("risk_score", 0)),
        reverse=True,
    )[:10]

    if important:
        lines.append("Most important findings:")
        lines.append("")

        for r in important:
            path = r.get("path", "")
            name = Path(path).name if path else "Unknown file"
            detections = r.get("detections", []) or []

            if detections:
                first = detections[0]
                reason = f"{first.get('name', 'Finding')} - {first.get('details', '')}"
            else:
                reason = "No specific finding available."

            lines.extend(
                [
                    f"- File: {path or name}",
                    f"  Verdict: {r.get('verdict', 'Unknown')}",
                    f"  Trust / risk: {r.get('trust_label', '')}",
                    f"  AI result: {r.get('model_type', 'Not available')}",
                    f"  Main reason: {reason}",
                    "  Action: Review this file before opening it." if r.get("verdict") != "Clean" else "  Action: No action required.",
                    "",
                ]
            )

    return "\n".join(lines)


def _compact_results_for_llm(results: list[dict[str, Any]], max_items: int = 20) -> dict[str, Any]:
    compact = []

    sorted_results = sorted(
        results,
        key=lambda r: _safe_int(r.get("risk_score", 0)),
        reverse=True,
    )[:max_items]

    for r in sorted_results:
        detections = []

        for d in (r.get("detections", []) or [])[:5]:
            detections.append(
                {
                    "engine": d.get("engine", ""),
                    "name": d.get("name", ""),
                    "severity": d.get("severity", 0),
                    "category": d.get("category", ""),
                    "details": d.get("details", ""),
                }
            )

        compact.append(
            {
                "file": Path(r.get("path", "")).name,
                "path": r.get("path", ""),
                "verdict": r.get("verdict", ""),
                "risk_score": r.get("risk_score", 0),
                "trust_label": r.get("trust_label", ""),
                "model_engine": r.get("model_engine", ""),
                "model_type": r.get("model_type", ""),
                "model_confidence": r.get("model_confidence", 0),
                "quarantined": bool(r.get("quarantined")),
                "detections": detections,
            }
        )

    summary = {
        "total": len(results),
        "clean": sum(1 for r in results if r.get("verdict") == "Clean"),
        "review": sum(1 for r in results if r.get("verdict") == "Review needed"),
        "high_risk": sum(1 for r in results if r.get("verdict") in {"Malicious", "High risk", "High-risk malware"}),
        "errors": sum(1 for r in results if r.get("verdict") == "Error"),
        "quarantined": sum(1 for r in results if r.get("quarantined")),
    }

    return {
        "summary": summary,
        "most_important_items": compact,
    }


def _build_scan_prompt(results: list[dict[str, Any]]) -> str:
    data = _compact_results_for_llm(results)

    return f"""
You are a cybersecurity reporting assistant inside a local desktop antivirus application.

Write a clear, professional scan report for a normal Windows user.
Do not use JSON.
Do not exaggerate.
Explain what happened, what is risky, and what the user should do.
Mention that EICAR is a standard antivirus test file if it appears.
Use short sections.

Scan data:
{json.dumps(data, indent=2, ensure_ascii=False)}
""".strip()


def generate_with_ollama(prompt: str, model: str | None = None) -> str:
    ok, selected_model, msg = ensure_ollama_model()

    if not ok:
        raise RuntimeError(msg)

    payload = {
        "model": model or selected_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_ctx": 4096,
        },
    }

    try:
        data = _post_json(
            f"{OLLAMA_HOST}/api/generate",
            payload,
            timeout=240,
        )
        return str(data.get("response", "")).strip()

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama HTTP {exc.code}: {body}")

    except Exception as exc:
        raise RuntimeError(f"Ollama generation failed: {exc}")


def generate_scan_ai_report(results: list[dict[str, Any]]) -> str:
    local_report = _summarize_scan_locally(results)

    try:
        prompt = _build_scan_prompt(results)
        ollama_report = generate_with_ollama(prompt)

        if ollama_report:
            return ollama_report

        return local_report + "\n\nLocal Ollama report unavailable: empty response."

    except Exception as exc:
        return local_report + f"\n\nLocal Ollama report unavailable: {exc}"


def generate_network_ai_report(result: dict[str, Any]) -> str:
    summary = result.get("summary", {}) or {}
    findings = result.get("findings", []) or []
    connections = result.get("connections", []) or []
    cicids = result.get("cicids_ai", {}) or {}

    local_lines = [
        "AI network report",
        "",
        f"Connections found: {summary.get('total_connections', len(connections))}",
        f"Findings to review: {summary.get('suspicious_findings', len(findings))}",
        f"External connections: {summary.get('external_connections', 0)}",
        f"Listening services: {summary.get('listening_services', 0)}",
        f"Highest risk: {summary.get('highest_risk', 0)}/100",
        "",
    ]

    if cicids:
        local_lines.append(f"Network AI: {cicids.get('summary', 'No CICIDS summary available.')}")
        local_lines.append("")

    if findings:
        local_lines.append("Findings to review:")
        for f in findings[:10]:
            local_lines.append(
                f"- {f.get('process_name', 'Unknown process')} "
                f"PID {f.get('pid', '')}, risk {f.get('severity', 0)}/100: "
                f"{f.get('reason', f.get('details', ''))}"
            )
    else:
        local_lines.append("No risky network connection was detected by the local checks.")

    local_report = "\n".join(local_lines)

    compact = {
        "summary": summary,
        "cicids_ai": cicids,
        "findings": findings[:15],
        "connections_sample": connections[:20],
    }

    prompt = f"""
You are a cybersecurity network reporting assistant inside a local desktop security application.

Write a clear network audit report for a normal Windows user.
Do not use JSON.
Do not exaggerate.
Explain whether anything needs attention.

Network data:
{json.dumps(compact, indent=2, ensure_ascii=False, default=str)}
""".strip()

    try:
        report = generate_with_ollama(prompt)
        return report if report else local_report
    except Exception as exc:
        return local_report + f"\n\nLocal Ollama network report unavailable: {exc}"


def gemini_status() -> dict[str, Any]:
    """
    Kept for compatibility with the old app code.
    This project now uses Ollama, not Gemini.
    """
    installed = _ollama_binary_exists()

    if installed:
        _start_ollama_server_if_needed()

    models = _installed_ollama_models() if installed else set()

    return {
        "provider": "ollama",
        "google_genai_installed": False,
        "api_key_configured": False,
        "ollama_installed": installed,
        "ollama_host": OLLAMA_HOST,
        "ollama_model": OLLAMA_MODEL,
        "ollama_fallback_model": OLLAMA_FALLBACK_MODEL,
        "model_installed": OLLAMA_MODEL in models or OLLAMA_FALLBACK_MODEL in models,
        "installed_models": sorted(models),
    }


def ollama_status() -> dict[str, Any]:
    return gemini_status()