from __future__ import annotations

import hashlib
import json
import textwrap
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from .config import REPORTS_DIR
from .gemini_reporter import generate_scan_ai_report

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
except Exception:
    A4 = None
    canvas = None
    colors = None


_AI_REPORT_CACHE: dict[str, str] = {}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _result_cache_key(results: list[dict[str, Any]]) -> str:
    compact = []

    for r in results:
        compact.append(
            {
                "path": r.get("path", ""),
                "sha256": r.get("sha256", ""),
                "verdict": r.get("verdict", ""),
                "risk_score": r.get("risk_score", r.get("score", 0)),
                "model_engine": r.get("model_engine", ""),
                "model_type": r.get("model_type", ""),
                "model_confidence": r.get("model_confidence", 0),
                "detections": [
                    {
                        "engine": d.get("engine", ""),
                        "name": d.get("name", ""),
                        "severity": d.get("severity", 0),
                        "details": d.get("details", ""),
                    }
                    for d in (r.get("detections", []) or [])[:10]
                ],
            }
        )

    raw = json.dumps(compact, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def get_cached_ai_report(results: list[dict[str, Any]]) -> str:
    key = _result_cache_key(results)

    if key not in _AI_REPORT_CACHE:
        _AI_REPORT_CACHE[key] = generate_scan_ai_report(results)

    return _AI_REPORT_CACHE[key]


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(results),
        "clean": sum(1 for r in results if r.get("verdict") == "Clean"),
        "review": sum(1 for r in results if r.get("verdict") == "Review needed"),
        "malicious": sum(
            1
            for r in results
            if r.get("verdict") in {"Malicious", "High risk", "High-risk malware"}
        ),
        "errors": sum(1 for r in results if r.get("verdict") == "Error"),
        "quarantined": sum(1 for r in results if r.get("quarantined")),
    }


def _risk_score(result: dict[str, Any]) -> int:
    try:
        return int(result.get("risk_score", result.get("score", 0)) or 0)
    except Exception:
        return 0


def _risk_class(score: int) -> str:
    if score >= 70:
        return "risk-high"
    if score >= 40:
        return "risk-medium"
    if score >= 20:
        return "risk-low-medium"
    return "risk-low"


def _risk_label(score: int) -> str:
    if score >= 70:
        return "High risk"
    if score >= 40:
        return "Review recommended"
    if score >= 20:
        return "Low-medium risk"
    return "Low risk"


def _confidence_text(value: Any) -> str:
    try:
        return f"{float(value or 0):.2%}"
    except Exception:
        return "0.00%"


def _safe_name(path: str) -> str:
    try:
        return Path(path).name or path
    except Exception:
        return str(path or "")


def _main_finding(result: dict[str, Any]) -> str:
    detections = result.get("detections", []) or []

    if not detections:
        return "No rule-based finding"

    first = detections[0]
    engine = first.get("engine") or first.get("detector") or "Scanner"
    name = first.get("name") or "Unnamed finding"

    return f"{engine}: {name}"


def generate_plain_explanation(results: list[dict[str, Any]]) -> str:
    return get_cached_ai_report(results)


def generate_html_report(results: list[dict[str, Any]]) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    stamp = _now_utc().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"whealth_scan_report_{stamp}.html"

    summary = summarize_results(results)
    ai_report = get_cached_ai_report(results)

    sorted_results = sorted(results, key=_risk_score, reverse=True)

    rows_html = []

    for r in sorted_results:
        score = _risk_score(r)
        risk_class = _risk_class(score)
        file_name = _safe_name(r.get("path", ""))

        rows_html.append(
            f"""
            <tr>
                <td>
                    <div class="file-name">{escape(file_name)}</div>
                    <div class="file-path">{escape(r.get("path", ""))}</div>
                </td>
                <td><span class="badge {risk_class}">{escape(r.get("verdict", "Unknown"))}</span></td>
                <td><strong>{score}/100</strong><br><span class="muted">{_risk_label(score)}</span></td>
                <td>
                    <div><strong>{escape(r.get("model_engine", "Not available") or "Not available")}</strong></div>
                    <div>{escape(r.get("model_type", "Not available") or "Not available")}</div>
                    <div class="muted">Confidence: {_confidence_text(r.get("model_confidence", 0))}</div>
                </td>
                <td>{escape(_main_finding(r))}</td>
                <td>{escape("Yes" if r.get("quarantined") else "No")}</td>
            </tr>
            """
        )

    detail_cards = []

    for r in sorted_results[:30]:
        score = _risk_score(r)
        risk_class = _risk_class(score)
        file_name = _safe_name(r.get("path", ""))
        detections = r.get("detections", []) or []

        finding_items = []

        if detections:
            for d in detections[:8]:
                engine = d.get("engine") or d.get("detector") or "Scanner"
                name = d.get("name", "Unnamed finding")
                severity = d.get("severity", 0)
                category = d.get("category", "")
                details = d.get("details", "")

                finding_items.append(
                    f"""
                    <li>
                        <strong>{escape(engine)}</strong>
                        {f"<span class='mini-tag'>{escape(category)}</span>" if category else ""}
                        — {escape(name)}
                        <span class="muted">({escape(str(severity))}/100)</span>
                        <br>
                        <span class="muted">{escape(details)}</span>
                    </li>
                    """
                )
        else:
            finding_items.append("<li class='muted'>No rule-based finding was detected.</li>")

        detail_cards.append(
            f"""
            <section class="detail-card">
                <div class="detail-header">
                    <div>
                        <h3>{escape(file_name)}</h3>
                        <p>{escape(r.get("path", ""))}</p>
                    </div>
                    <span class="badge {risk_class}">{score}/100</span>
                </div>

                <div class="detail-grid">
                    <div>
                        <span class="label">Final verdict</span>
                        <strong>{escape(r.get("trust_label", r.get("verdict", "Unknown")))}</strong>
                    </div>
                    <div>
                        <span class="label">AI model</span>
                        <strong>{escape(r.get("model_engine", "Not available") or "Not available")}</strong>
                    </div>
                    <div>
                        <span class="label">AI opinion</span>
                        <strong>{escape(r.get("model_type", "Not available") or "Not available")}</strong>
                    </div>
                    <div>
                        <span class="label">AI confidence</span>
                        <strong>{_confidence_text(r.get("model_confidence", 0))}</strong>
                    </div>
                </div>

                <h4>Evidence</h4>
                <ul>{''.join(finding_items)}</ul>

                <h4>SHA-256</h4>
                <code>{escape(r.get("sha256", ""))}</code>
            </section>
            """
        )

    generated_at = _now_utc().isoformat(timespec="seconds")

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WHealth AI Scan Report</title>
<style>
:root {{
    --red: #C0392B;
    --red-dark: #96281B;
    --red-soft: #FADBD8;
    --green: #1E8449;
    --green-soft: #D5F5E3;
    --amber: #B7770D;
    --amber-soft: #FEF9E7;
    --gray-50: #FAFAFA;
    --gray-100: #F5F5F5;
    --gray-200: #EEEEEE;
    --gray-500: #9E9E9E;
    --gray-700: #616161;
    --gray-900: #212121;
    --white: #FFFFFF;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: linear-gradient(135deg, #fff 0%, #f8f1f0 100%);
    color: var(--gray-900);
    font-family: "Segoe UI", Arial, sans-serif;
}}

.page {{
    max-width: 1280px;
    margin: auto;
    padding: 36px;
}}

.hero {{
    background: linear-gradient(135deg, var(--red) 0%, var(--red-dark) 100%);
    color: white;
    border-radius: 22px;
    padding: 32px;
    box-shadow: 0 18px 45px rgba(150, 40, 27, 0.25);
}}

.hero h1 {{
    margin: 0;
    font-size: 34px;
    letter-spacing: -0.5px;
}}

.hero p {{
    margin: 8px 0 0;
    opacity: 0.9;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin: 22px 0;
}}

.card {{
    background: white;
    border: 1px solid var(--gray-200);
    border-radius: 18px;
    padding: 18px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.05);
}}

.card b {{
    color: var(--gray-500);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.card h2 {{
    margin: 8px 0 0;
    font-size: 32px;
}}

.panel {{
    background: white;
    border: 1px solid var(--gray-200);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 22px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.05);
}}

.panel h2 {{
    margin: 0 0 14px;
}}

.ai-report {{
    white-space: pre-wrap;
    line-height: 1.6;
    font-family: "Segoe UI", Arial, sans-serif;
    background: var(--gray-50);
    border: 1px solid var(--gray-200);
    border-radius: 14px;
    padding: 18px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    overflow: hidden;
    border-radius: 14px;
}}

th {{
    background: var(--gray-50);
    color: var(--gray-700);
    text-align: left;
    padding: 12px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    border-bottom: 2px solid var(--gray-200);
}}

td {{
    padding: 14px 12px;
    border-bottom: 1px solid var(--gray-200);
    vertical-align: top;
    font-size: 13px;
}}

tr:hover {{
    background: #fff8f7;
}}

.file-name {{
    font-weight: 700;
}}

.file-path {{
    color: var(--gray-500);
    font-size: 12px;
    margin-top: 4px;
    word-break: break-all;
}}

.badge {{
    display: inline-block;
    border-radius: 999px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 800;
}}

.risk-high {{
    background: var(--red-soft);
    color: var(--red-dark);
}}

.risk-medium {{
    background: var(--amber-soft);
    color: var(--amber);
}}

.risk-low-medium {{
    background: #FDEBD0;
    color: #A04000;
}}

.risk-low {{
    background: var(--green-soft);
    color: var(--green);
}}

.muted {{
    color: var(--gray-500);
    font-size: 12px;
}}

.detail-card {{
    border: 1px solid var(--gray-200);
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 16px;
    background: white;
}}

.detail-header {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    border-bottom: 1px solid var(--gray-200);
    padding-bottom: 12px;
    margin-bottom: 14px;
}}

.detail-header h3 {{
    margin: 0;
}}

.detail-header p {{
    margin: 5px 0 0;
    color: var(--gray-500);
    font-size: 12px;
    word-break: break-all;
}}

.detail-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 14px;
}}

.detail-grid div {{
    background: var(--gray-50);
    border: 1px solid var(--gray-200);
    border-radius: 12px;
    padding: 12px;
}}

.label {{
    display: block;
    color: var(--gray-500);
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 5px;
}}

h4 {{
    margin-bottom: 8px;
}}

li {{
    margin-bottom: 8px;
}}

.mini-tag {{
    background: var(--gray-100);
    color: var(--gray-700);
    border-radius: 6px;
    padding: 2px 6px;
    font-size: 10px;
    font-weight: 700;
}}

code {{
    display: block;
    background: var(--gray-50);
    border: 1px solid var(--gray-200);
    border-radius: 10px;
    padding: 10px;
    word-break: break-all;
    color: var(--gray-700);
}}

.footer {{
    text-align: center;
    color: var(--gray-500);
    font-size: 12px;
    margin-top: 30px;
}}
</style>
</head>
<body>
<div class="page">

    <section class="hero">
        <h1>WHealth AI Scan Report</h1>
        <p>Generated at {escape(generated_at)} UTC</p>
        <p>AI reporting provider: local Ollama if configured, with local fallback if unavailable.</p>
    </section>

    <section class="cards">
        <div class="card"><b>Total scanned</b><h2>{summary["total"]}</h2></div>
        <div class="card"><b>Trusted</b><h2>{summary["clean"]}</h2></div>
        <div class="card"><b>Need review</b><h2>{summary["review"]}</h2></div>
        <div class="card"><b>High risk</b><h2>{summary["malicious"]}</h2></div>
        <div class="card"><b>Quarantined</b><h2>{summary["quarantined"]}</h2></div>
    </section>

    <section class="panel">
        <h2>AI Security Summary</h2>
        <div class="ai-report">{escape(ai_report)}</div>
    </section>

    <section class="panel">
        <h2>Scan Results Table</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Verdict</th>
                    <th>Risk</th>
                    <th>AI classification</th>
                    <th>Main finding</th>
                    <th>Quarantine</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </section>

    <section class="panel">
        <h2>Detailed File Analysis</h2>
        {''.join(detail_cards) if detail_cards else "<p>No file details available.</p>"}
    </section>

    <div class="footer">
        WHealth Security Suite — Static rules, PE checks, entropy analysis, and MalVisor AI classification.
    </div>

</div>
</body>
</html>
"""

    path.write_text(html, encoding="utf-8")
    return str(path)


def _pdf_draw_wrapped_text(
    c: Any,
    text: str,
    x: float,
    y: float,
    max_chars: int = 95,
    line_height: int = 13,
    bottom_margin: int = 50,
) -> float:
    width, height = A4

    for paragraph in str(text or "").splitlines():
        wrapped = textwrap.wrap(paragraph, width=max_chars) or [""]

        for line in wrapped:
            if y < bottom_margin:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 9)

            c.drawString(x, y, line[:max_chars])
            y -= line_height

    return y


def generate_pdf_report(results: list[dict[str, Any]]) -> str:
    if canvas is None or A4 is None:
        return ""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    stamp = _now_utc().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"whealth_scan_report_{stamp}.pdf"

    summary = summarize_results(results)
    ai_report = get_cached_ai_report(results)
    sorted_results = sorted(results, key=_risk_score, reverse=True)

    c = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 50

    # Header
    if colors is not None:
        c.setFillColor(colors.HexColor("#C0392B"))
        c.rect(0, height - 95, width, 95, fill=True, stroke=False)
        c.setFillColor(colors.white)

    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 45, "WHealth AI Scan Report")

    c.setFont("Helvetica", 9)
    c.drawString(40, height - 65, f"Generated at {_now_utc().isoformat(timespec='seconds')} UTC")
    c.drawString(40, height - 80, "Provider: Ollama local if configured, with local fallback if unavailable")

    y = height - 125

    if colors is not None:
        c.setFillColor(colors.black)

    # Summary cards as text
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Summary")
    y -= 20

    c.setFont("Helvetica", 10)
    summary_line = (
        f"Total: {summary['total']}   "
        f"Trusted: {summary['clean']}   "
        f"Review: {summary['review']}   "
        f"High risk: {summary['malicious']}   "
        f"Quarantined: {summary['quarantined']}"
    )
    c.drawString(40, y, summary_line)
    y -= 30

    # AI report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "AI Security Summary")
    y -= 18

    c.setFont("Helvetica", 9)
    y = _pdf_draw_wrapped_text(c, ai_report, 40, y, max_chars=105, line_height=12)
    y -= 18

    # Important files
    if y < 120:
        c.showPage()
        y = height - 50

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Important Files")
    y -= 20

    for r in sorted_results[:25]:
        score = _risk_score(r)
        file_name = _safe_name(r.get("path", ""))
        verdict = r.get("verdict", "Unknown")
        ai_type = r.get("model_type", "Not available") or "Not available"
        confidence = _confidence_text(r.get("model_confidence", 0))
        main = _main_finding(r)

        block = (
            f"{file_name} | {verdict} | Risk {score}/100 | "
            f"AI: {ai_type} ({confidence}) | Finding: {main}"
        )

        if y < 70:
            c.showPage()
            y = height - 50

        c.setFont("Helvetica-Bold", 9)
        c.drawString(40, y, file_name[:95])
        y -= 12

        c.setFont("Helvetica", 8)
        y = _pdf_draw_wrapped_text(c, block, 55, y, max_chars=100, line_height=10)
        y -= 8

    c.save()
    return str(path)