from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from .config import DB_PATH


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    names = {row["name"] for row in rows}
    if column not in names:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                trust_label TEXT,
                model_engine TEXT,
                model_type TEXT,
                model_confidence REAL,
                quarantined INTEGER NOT NULL DEFAULT 0,
                quarantine_path TEXT,
                report_html TEXT,
                report_pdf TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                engine TEXT NOT NULL,
                name TEXT NOT NULL,
                severity INTEGER NOT NULL,
                category TEXT,
                details TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                path TEXT,
                details TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS behavior_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                score INTEGER NOT NULL,
                details TEXT
            )
            """
        )

        # Backward-compatible columns for older databases.
        for col, definition in [
            ("trust_label", "TEXT"),
            ("model_engine", "TEXT"),
            ("model_type", "TEXT"),
            ("model_confidence", "REAL"),
            ("report_html", "TEXT"),
            ("report_pdf", "TEXT"),
        ]:
            try:
                ensure_column(conn, "scans", col, definition)
            except Exception:
                pass


def save_scan(result: dict[str, Any]) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                scanned_at, path, sha256, verdict, risk_score, trust_label,
                model_engine, model_type, model_confidence, quarantined,
                quarantine_path, report_html, report_pdf
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                result.get("path", ""),
                result.get("sha256", ""),
                result.get("verdict", "Unknown"),
                int(result.get("risk_score", 0)),
                result.get("trust_label", ""),
                result.get("model_engine", ""),
                result.get("model_type", ""),
                float(result.get("model_confidence", 0.0) or 0.0),
                1 if result.get("quarantined") else 0,
                result.get("quarantine_path", ""),
                result.get("report_html", ""),
                result.get("report_pdf", ""),
            ),
        )
        scan_id = int(cur.lastrowid)

        for det in result.get("detections", []) or []:
            conn.execute(
                """
                INSERT INTO detections (scan_id, engine, name, severity, category, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    det.get("engine") or det.get("detector") or "Scanner",
                    det.get("name", "Detection"),
                    int(det.get("severity", 0) or 0),
                    det.get("category", ""),
                    det.get("details", ""),
                ),
            )
        return scan_id


def list_scans(limit: int = 200, verdict: str | None = None) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if verdict:
            rows = conn.execute(
                "SELECT * FROM scans WHERE verdict = ? ORDER BY id DESC LIMIT ?",
                (verdict, int(limit)),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(row) for row in rows]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        return dict(row) if row else None


def list_detections(scan_id: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM detections WHERE scan_id = ? ORDER BY severity DESC", (int(scan_id),)).fetchall()
        return [dict(row) for row in rows]


def save_system_events(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    with get_conn() as conn:
        for event in events:
            conn.execute(
                """
                INSERT INTO system_events (created_at, source, category, severity, title, path, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("created_at") or utc_now(),
                    event.get("source", "System"),
                    event.get("category", "General"),
                    int(event.get("severity", 0) or 0),
                    event.get("title", "Event"),
                    event.get("path", ""),
                    event.get("details", ""),
                ),
            )
        return len(events)


def list_system_events(limit: int = 200) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM system_events ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(row) for row in rows]


def clear_system_events() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM system_events")


def dashboard_stats() -> dict[str, int]:
    scans = list_scans(10000)
    total = len(scans)
    clean = sum(1 for s in scans if s.get("verdict") == "Clean")
    review = sum(1 for s in scans if s.get("verdict") == "Review needed")
    malicious = sum(1 for s in scans if s.get("verdict") in {"Malicious", "High risk"})
    errors = sum(1 for s in scans if s.get("verdict") == "Error")
    quarantined = sum(1 for s in scans if int(s.get("quarantined") or 0) == 1)
    events = list_system_events(10000)
    high_events = sum(1 for e in events if int(e.get("severity") or 0) >= 70)
    return {
        "total": total,
        "clean": clean,
        "review": review,
        "malicious": malicious,
        "errors": errors,
        "quarantined": quarantined,
        "system_events": len(events),
        "high_events": high_events,
    }
