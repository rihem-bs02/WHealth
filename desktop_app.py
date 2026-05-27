from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal, QRectF, QUrl, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QRect
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QPainter, QPen, QLinearGradient, QBrush, QPainterPath, QPixmap, QRadialGradient, QIcon, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QStackedWidget,
    QSizePolicy,
    QTextEdit,
    QGraphicsDropShadowEffect,
)

from app.config import REPORTS_DIR, SCAN_TARGETS_DIR, QUARANTINE_DIR, RULES_DIR
from app.database import (
    dashboard_stats,
    init_db,
    list_scans,
    list_system_events,
    save_scan,
    save_system_events,
)
from app.scanner import collect_scan_targets, scan_file
from app.reports import generate_html_report, generate_pdf_report, generate_plain_explanation
from app.malvisor_predictor import malvisor_status
from app.network_audit import run_network_audit, format_network_report_for_user
from app.system_scanners import (
    run_usb_scan,
    scan_startup_items,
    scan_scheduled_tasks,
    scan_process_behavior,
    scan_memory_processes,
)
from app.quarantine_manager import (
    list_quarantine_items,
    restore_quarantine_item,
    delete_quarantine_item,
)

try:
    from app.network_flow_features import capture_cicids_flows
except Exception:
    def capture_cicids_flows(duration: int = 15, max_packets: int = 3000, iface: str | None = None) -> dict:
        return {
            "ok": False,
            "error": "network_flow_features.py is missing or failed to import.",
            "flows": [],
            "packet_count": 0,
            "flow_count": 0,
            "duration": duration,
        }


try:
    from app.network_ai_cicids import run_optional_cicids_ai, cicids_ai_status
except Exception:
    def run_optional_cicids_ai(result: dict) -> dict:
        return {
            "ran": False,
            "status": "unavailable",
            "summary": "Advanced traffic pattern review is not available. The app will still show active connections and basic risk checks.",
            "predictions": [],
        }

    def cicids_ai_status() -> dict:
        return {
            "available": False,
            "reason": "Advanced traffic pattern review is not available.",
        }


try:
    from app.gemini_reporter import generate_network_ai_report, gemini_status
except Exception:
    def generate_network_ai_report(result: dict) -> str:
        return format_network_report_for_user(result)

    def gemini_status() -> dict:
        return {
            "google_genai_installed": False,
            "api_key_configured": False,
        }


try:
    from app.system_inventory import collect_system_checked_items
except Exception:
    def collect_system_checked_items(action: str, manual_path: str = "") -> list[dict]:
        return []


try:
    import yara
except Exception:
    yara = None


# ─────────────────────────────────────────────
#  DESIGN TOKENS
# ─────────────────────────────────────────────
# Font stack: Poppins gives the interface a cleaner, more premium feel.
# Qt will safely fall back to Segoe UI / Arial if Poppins is not installed.
UI_FONT_QT     = "Poppins"
FONT_STACK     = "'Poppins', 'Segoe UI Variable', 'Segoe UI', Arial"
MONO_FONT      = "'JetBrains Mono', 'Consolas', 'Courier New'"

# Professional red security palette + softer surfaces for immediate table readability.
RED_PRIMARY    = "#D7263D"
RED_DARK       = "#A3162D"
RED_DEEPER     = "#6E0F1D"
RED_LIGHT      = "#FCE7EB"
RED_SOFT       = "#FFF1F3"
RED_ACCENT     = "#FF4D5E"
RED_BORDER     = "#F8B4BE"
WHITE          = "#FFFFFF"
OFF_WHITE      = "#FFFDFD"
GRAY_50        = "#F8FAFC"
GRAY_100       = "#F1F5F9"
GRAY_200       = "#E2E8F0"
GRAY_300       = "#CBD5E1"
GRAY_500       = "#64748B"
GRAY_700       = "#334155"
GRAY_900       = "#0F172A"
GREEN_OK       = "#15803D"
GREEN_LIGHT    = "#E8F8EF"
AMBER_WARN     = "#B45309"
AMBER_LIGHT    = "#FFF4D6"
BLUE_INFO      = "#1D4ED8"
BLUE_LIGHT     = "#EAF2FF"
ICON_COLOR     = RED_PRIMARY
TABLE_ALT      = "#FBFCFE"
TABLE_HOVER    = "#FFF7F8"
TABLE_BORDER   = "#E2E8F0"
TABLE_HEADER   = "#8F1227"
TABLE_HEADER_HOVER = RED_DARK
TABLE_SELECTED = RED_DARK
SIDEBAR_BG     = "#16070B"
SIDEBAR_HOVER  = "#2A0D14"
SIDEBAR_ACTIVE = "#D7263D"


def format_eta(seconds: float) -> str:
    try:
        seconds = max(0, int(seconds))
    except Exception:
        seconds = 0
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


# ─────────────────────────────────────────────
#  WORKER THREADS (unchanged logic)
# ─────────────────────────────────────────────

class ScanWorker(QThread):
    progress = Signal(int, str)
    finished = Signal(list, str, str, str)
    failed = Signal(str)

    def __init__(self, path: str, quarantine: bool = False):
        super().__init__()
        self.path = path
        self.quarantine = quarantine

    def emit_progress(self, value: int, message: str):
        self.progress.emit(max(0, min(100, int(value))), message)

    def run(self):
        try:
            start = time.monotonic()
            self.emit_progress(0, "Preparing file list")
            files = collect_scan_targets(self.path)
            if not files:
                self.failed.emit("No files were found at the selected path.")
                return
            results = []
            total = len(files)
            for i, path in enumerate(files, start=1):
                elapsed = max(0.1, time.monotonic() - start)
                avg = elapsed / max(1, i - 1) if i > 1 else 0
                eta = avg * max(0, total - i + 1) if avg else 0
                percent = int(((i - 1) / max(1, total)) * 82)
                self.emit_progress(percent, f"Scanning {i}/{total} files — {format_eta(eta)} remaining")
                result = scan_file(str(path), quarantine=self.quarantine)
                results.append(result)
            self.emit_progress(86, "Building report")
            html_report = ""
            pdf_report = ""
            explanation = generate_plain_explanation(results)
            try:
                html_report = generate_html_report(results)
            except Exception as exc:
                explanation += f"\n\nHTML report could not be generated: {exc}"
            self.emit_progress(92, "Building PDF report")
            try:
                pdf_report = generate_pdf_report(results)
            except Exception as exc:
                explanation += f"\n\nPDF report could not be generated: {exc}"
            html_name = Path(html_report).name if html_report else ""
            pdf_name = Path(pdf_report).name if pdf_report else ""
            for j, result in enumerate(results, start=1):
                result["report_html"] = html_name
                result["report_pdf"] = pdf_name
                save_scan(result)
                self.emit_progress(92 + int(7 * j / max(1, len(results))), f"Saving result {j}/{len(results)}")
            self.emit_progress(100, f"Scan complete — {len(results)} file(s) checked.")
            self.finished.emit(results, html_report, pdf_report, explanation)
        except Exception as exc:
            self.failed.emit(str(exc))


class ActionWorker(QThread):
    progress = Signal(int, str)
    finished = Signal(str, object)
    failed = Signal(str)

    def __init__(self, action: str, quarantine: bool = False, manual_path: str = ""):
        super().__init__()
        self.action = action
        self.quarantine = quarantine
        self.manual_path = manual_path

    def run(self):
        try:
            self.progress.emit(10, "Starting task")
            if self.action == "network":
                self.progress.emit(20, "Reading active network connections")
                result = run_network_audit()
                self.progress.emit(35, "Taking a short network traffic sample — about 15 seconds")
                try:
                    flow_capture = capture_cicids_flows(duration=15, max_packets=3000)
                    result["flow_capture"] = flow_capture
                    result["flow_features"] = flow_capture.get("flows", []) if flow_capture.get("ok") else []
                except Exception as exc:
                    result["flow_capture"] = {"ok": False, "error": str(exc), "flows": [], "packet_count": 0, "flow_count": 0, "duration": 15}
                    result["flow_features"] = []
                self.progress.emit(70, "Reviewing network traffic patterns")
                try:
                    result["cicids_ai"] = run_optional_cicids_ai(result)
                except Exception as exc:
                    result["cicids_ai"] = {"ran": False, "status": "error", "summary": f"Traffic pattern review could not finish: {exc}", "predictions": []}
                self.progress.emit(88, "Generating network explanation")
                try:
                    result["ai_report"] = generate_network_ai_report(result)
                except Exception as exc:
                    result["ai_report"] = format_network_report_for_user(result) + f"\n\nDetailed explanation could not be generated: {exc}"
            elif self.action == "usb":
                self.progress.emit(35, "Scanning removable drive")
                result = run_usb_scan(self.quarantine, self.manual_path)
                if isinstance(result, dict):
                    result.setdefault("checked_items", collect_system_checked_items("usb", self.manual_path))
                save_system_events(result.get("events", []))
            elif self.action == "startup":
                self.progress.emit(50, "Checking startup entries")
                result = scan_startup_items()
                if isinstance(result, dict):
                    result.setdefault("checked_items", collect_system_checked_items("startup", self.manual_path))
                save_system_events(result.get("events", []))
            elif self.action == "tasks":
                self.progress.emit(50, "Checking scheduled tasks")
                result = scan_scheduled_tasks()
                if isinstance(result, dict):
                    result.setdefault("checked_items", collect_system_checked_items("tasks", self.manual_path))
                save_system_events(result.get("events", []))
            elif self.action == "process":
                self.progress.emit(50, "Checking process behavior")
                result = scan_process_behavior()
                if isinstance(result, dict):
                    result.setdefault("checked_items", collect_system_checked_items("process", self.manual_path))
                save_system_events(result.get("events", []))
            elif self.action == "memory":
                self.progress.emit(50, "Checking memory and process risk")
                result = scan_memory_processes()
                if isinstance(result, dict):
                    result.setdefault("checked_items", collect_system_checked_items("memory", self.manual_path))
                save_system_events(result.get("events", []))
            else:
                raise ValueError(f"Unknown task: {self.action}")
            self.progress.emit(100, "Task complete")
            self.finished.emit(self.action, result)
        except Exception as exc:
            self.failed.emit(str(exc))


# ─────────────────────────────────────────────
#  CUSTOM WIDGETS
# ─────────────────────────────────────────────

class SidebarButton(QPushButton):
    def __init__(self, icon_char: str, label: str, parent=None):
        super().__init__(parent)
        self._icon_char = icon_char
        self._label = label
        self._active = False
        self.setCheckable(False)
        self.setFixedHeight(52)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)
        self._update_style()

    def set_active(self, active: bool):
        self._active = active
        self._update_style()

    def _update_style(self):
        if self._active:
            bg = SIDEBAR_ACTIVE
            fg = WHITE
            fw = "700"
            br = "10px"
        else:
            bg = "transparent"
            fg = "#C9A09D"
            fw = "500"
            br = "10px"
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: none;
                border-radius: {br};
                text-align: left;
                padding: 0px 16px;
                font-size: 13px;
                font-weight: {fw};
                font-family: {FONT_STACK};
            }}
            QPushButton:hover {{
                background: {RED_DARK if self._active else SIDEBAR_HOVER};
            }}
        """)
        self.setText(f"  {self._icon_char}   {self._label}")


class StatCard(QFrame):
    clicked = Signal(str)

    def __init__(self, key: str, title: str, value: str = "0",
                 color: str = RED_PRIMARY, icon: str = "●"):
        super().__init__()
        self.key = key
        self._color = color
        self.setObjectName("statCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(110)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 30))
        self.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        self.icon_label = QLabel(icon)
        self.icon_label.setStyleSheet(
            f"font-size: 22px; color: {ICON_COLOR}; background: transparent; border: none;"
        )
        top_row.addWidget(self.icon_label)
        top_row.addStretch(1)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet(
            "font-size: 10px; font-weight: 700; letter-spacing: 1.2px; "
            "color: #9E9E9E; background: transparent; border: none;"
        )

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(
            f"font-size: 34px; font-weight: 800; color: {color}; "
            "background: transparent; border: none; font-family: {FONT_STACK};"
        )

        layout.addLayout(top_row)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: Any):
        self.value_label.setText(str(value))

    def mousePressEvent(self, event):
        self.clicked.emit(self.key)
        super().mousePressEvent(event)


class DonutChart(QWidget):
    clicked = Signal(str)

    def __init__(self):
        super().__init__()
        self.values = {"clean": 0, "review": 0, "malicious": 0, "errors": 0}
        self.colors = {
            "clean":     QColor(GREEN_OK),
            "review":    QColor(AMBER_WARN),
            "malicious": QColor(RED_ACCENT),
            "errors":    QColor(GRAY_500),
        }
        self.labels = {
            "clean": "Trusted",
            "review": "Review",
            "malicious": "High Risk",
            "errors": "Errors",
        }
        self.setMinimumHeight(200)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_values(self, **values):
        self.values.update({k: int(v) for k, v in values.items()})
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        total = sum(self.values.values())
        w, h = self.width(), self.height()
        chart_h = h - 40
        side = min(w * 0.5, chart_h) - 20
        cx = w * 0.32
        cy = chart_h / 2 + 10
        rect = QRectF(cx - side / 2, cy - side / 2, side, side)

        pen = QPen()
        pen.setWidth(26)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)

        if total <= 0:
            pen.setColor(QColor(GRAY_200))
            painter.setPen(pen)
            painter.drawEllipse(rect)
            painter.setPen(QColor(GRAY_700))
            painter.setFont(QFont(UI_FONT_QT, 12, QFont.Weight.DemiBold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No data")
        else:
            start = 90 * 16
            for key, value in self.values.items():
                if value <= 0:
                    continue
                span = -360.0 * value / total
                pen.setColor(self.colors[key])
                painter.setPen(pen)
                painter.drawArc(rect, int(start), int(span * 16))
                start += int(span * 16)

            # Center text
            painter.setPen(QColor(GRAY_900))
            painter.setFont(QFont(UI_FONT_QT, 20, QFont.Weight.Bold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(total))
            small_rect = QRectF(rect.x(), rect.y() + 26, rect.width(), rect.height())
            painter.setPen(QColor(GRAY_500))
            painter.setFont(QFont(UI_FONT_QT, 9))
            painter.drawText(small_rect, Qt.AlignmentFlag.AlignCenter, "total files")

        # Legend
        legend_x = w * 0.62
        legend_y = cy - len(self.values) * 18
        painter.setFont(QFont(UI_FONT_QT, 10, QFont.Weight.Medium))

        for i, (key, value) in enumerate(self.values.items()):
            y = legend_y + i * 36
            pct = f"{value / total * 100:.0f}%" if total > 0 else "0%"

            # colored dot
            dot_pen = QPen(self.colors[key])
            dot_pen.setWidth(0)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(self.colors[key]))
            painter.drawEllipse(int(legend_x), int(y + 3), 10, 10)

            painter.setPen(QColor(GRAY_700))
            painter.setFont(QFont(UI_FONT_QT, 10))
            painter.drawText(int(legend_x + 18), int(y + 13), self.labels[key])

            painter.setPen(QColor(GRAY_900))
            painter.setFont(QFont(UI_FONT_QT, 10, QFont.Weight.Bold))
            painter.drawText(int(legend_x + 90), int(y + 13), f"{value}  {pct}")

    def mousePressEvent(self, event):
        total = sum(self.values.values())
        if total <= 0:
            return
        x = event.position().x() / max(1, self.width())
        y = event.position().y() / max(1, self.height())
        if x < 0.5 and y < 0.55:
            self.clicked.emit("clean")
        elif x >= 0.5 and y < 0.55:
            self.clicked.emit("review")
        elif x < 0.5 and y >= 0.55:
            self.clicked.emit("malicious")
        else:
            self.clicked.emit("errors")
        super().mousePressEvent(event)


class SecuritySummaryCard(QFrame):
    """Clean, card-style security summary output - not terminal-looking."""

    def __init__(self, title: str = "Security Analysis", parent=None):
        super().__init__(parent)
        self.setObjectName("securityCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QFrame()
        header.setObjectName("securityCardHeader")
        header.setFixedHeight(42)
        hlayout = QHBoxLayout(header)
        hlayout.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("◆")
        icon.setStyleSheet(f"color: {WHITE}; font-size: 12px; background: transparent;")

        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(
            f"color: {WHITE}; font-size: 13px; font-weight: 700; "
            "letter-spacing: 0.5px; background: transparent;"
        )

        hlayout.addWidget(icon)
        hlayout.addSpacing(8)
        hlayout.addWidget(self._title_label)
        hlayout.addStretch(1)

        # Content area
        self._content = QTextEdit()
        self._content.setReadOnly(True)
        self._content.setObjectName("securityCardContent")

        layout.addWidget(header)
        layout.addWidget(self._content)

    def set_text(self, text: str):
        # Format the text nicely using HTML
        lines = text.strip().split("\n")
        html_parts = []
        in_section = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                if in_section:
                    html_parts.append("</div>")
                    in_section = False
                html_parts.append("<br>")
                continue

            # Section headers (lines ending with : or all caps short lines)
            if stripped.endswith(":") and len(stripped) < 60 and not stripped.startswith("-"):
                if in_section:
                    html_parts.append("</div>")
                    in_section = False
                html_parts.append(
                    f'<div class="section-header">{stripped}</div>'
                )
                in_section = True
                html_parts.append('<div class="section-body">')
            elif stripped.startswith("- ") or stripped.startswith("• "):
                text_part = stripped[2:]
                # Color-code severity keywords
                text_part = text_part.replace("HIGH", f'<span class="tag-red">HIGH</span>')
                text_part = text_part.replace("MEDIUM", f'<span class="tag-amber">MEDIUM</span>')
                text_part = text_part.replace("LOW", f'<span class="tag-green">LOW</span>')
                text_part = text_part.replace("CLEAN", f'<span class="tag-green">CLEAN</span>')
                text_part = text_part.replace("MALICIOUS", f'<span class="tag-red">MALICIOUS</span>')
                html_parts.append(f'<div class="list-item">▸ {text_part}</div>')
            else:
                html_parts.append(f'<p class="body-text">{stripped}</p>')

        if in_section:
            html_parts.append("</div>")

        css = f"""
        <style>
            body {{
                font-family: {FONT_STACK};
                font-size: 13px;
                color: {GRAY_900};
                margin: 0;
                padding: 0;
                line-height: 1.65;
            }}
            .section-header {{
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 1.5px;
                text-transform: uppercase;
                color: {RED_PRIMARY};
                margin: 18px 0 6px 0;
                padding-bottom: 4px;
                border-bottom: 1.5px solid {RED_LIGHT};
            }}
            .section-body {{
                margin: 0 0 4px 0;
            }}
            .list-item {{
                padding: 4px 0 4px 12px;
                color: {GRAY_700};
                font-size: 13px;
            }}
            .body-text {{
                color: {GRAY_700};
                margin: 4px 0;
            }}
            .tag-red {{
                background: {RED_LIGHT};
                color: {RED_DARK};
                font-weight: 700;
                padding: 1px 6px;
                border-radius: 4px;
                font-size: 11px;
            }}
            .tag-amber {{
                background: {AMBER_LIGHT};
                color: {AMBER_WARN};
                font-weight: 700;
                padding: 1px 6px;
                border-radius: 4px;
                font-size: 11px;
            }}
            .tag-green {{
                background: {GREEN_LIGHT};
                color: {GREEN_OK};
                font-weight: 700;
                padding: 1px 6px;
                border-radius: 4px;
                font-size: 11px;
            }}
        </style>
        """
        self._content.setHtml(css + "".join(html_parts))

    def set_plain(self, text: str):
        self.set_text(text)


class RiskBadge(QLabel):
    def __init__(self, text: str, level: str = "low", parent=None):
        super().__init__(text, parent)
        colors = {
            "high":   (RED_LIGHT, RED_DARK),
            "medium": (AMBER_LIGHT, AMBER_WARN),
            "low":    (GREEN_LIGHT, GREEN_OK),
            "info":   ("#EBF5FB", "#1A5276"),
        }
        bg, fg = colors.get(level, (GRAY_100, GRAY_700))
        self.setStyleSheet(
            f"background: {bg}; color: {fg}; border-radius: 6px; "
            f"padding: 2px 10px; font-size: 11px; font-weight: 700;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class ProtectionStatusWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("protectionWidget")
        self.setFixedHeight(220)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = QLabel("Protection Status")
        title.setObjectName("panelTitle")

        self._status_icon = QLabel("◆")
        self._status_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_icon.setStyleSheet(f"font-size: 42px; color: {ICON_COLOR}; background: transparent;")

        self._status_text = QLabel("Initializing...")
        self._status_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_text.setWordWrap(True)
        self._status_text.setStyleSheet(
            f"font-size: 13px; font-weight: 600; color: {GRAY_700}; background: transparent;"
        )

        self._model_label = QLabel("")
        self._model_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._model_label.setWordWrap(True)
        self._model_label.setStyleSheet(
            f"font-size: 11px; color: {GRAY_500}; background: transparent;"
        )

        layout.addWidget(title)
        layout.addWidget(self._status_icon)
        layout.addWidget(self._status_text)
        layout.addWidget(self._model_label)
        layout.addStretch(1)

    def update_status(self, malicious: int, review: int, total: int,
                       model_info: str = "", gemini_info: str = ""):
        if malicious:
            self._status_icon.setText("!")
            self._status_text.setText(
                f"<span style='color:{RED_PRIMARY}; font-weight:800; font-size:15px;'>"
                f"{malicious} High-Risk File(s) Detected</span><br>"
                f"<span style='color:{GRAY_700}'>Immediate action recommended.</span>"
            )
            self._status_text.setTextFormat(Qt.TextFormat.RichText)
        elif review:
            self._status_icon.setText("?")
            self._status_text.setText(
                f"<span style='color:{AMBER_WARN}; font-weight:700;'>"
                f"{review} File(s) Need Review</span>"
            )
            self._status_text.setTextFormat(Qt.TextFormat.RichText)
        elif total:
            self._status_icon.setText("✓")
            self._status_text.setText(
                f"<span style='color:{GREEN_OK}; font-weight:700;'>"
                f"All Clear — No Threats Found</span>"
            )
            self._status_text.setTextFormat(Qt.TextFormat.RichText)
        else:
            self._status_icon.setText("◆")
            self._status_text.setText("No scans have been run yet.")
            self._status_text.setTextFormat(Qt.TextFormat.PlainText)

        self._model_label.setText(f"{model_info}   {gemini_info}")


class SectionHeader(QLabel):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setObjectName("panelTitle")


class WHealthProgressBar(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRange(0, 100)
        self.setFixedHeight(8)
        self.setTextVisible(False)
        self.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 4px;
                background: {GRAY_200};
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {RED_ACCENT}, stop:1 {RED_PRIMARY});
            }}
        """)


# ─────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────

class WHealthDesktop(QMainWindow):
    def __init__(self):
        super().__init__()

        init_db()

        self.scan_worker: ScanWorker | None = None
        self.action_worker: ActionWorker | None = None
        self.last_scan_results: list[dict[str, Any]] = []
        self.last_html_report = ""
        self.last_pdf_report = ""
        self.dashboard_filter = "all"

        self.setWindowTitle("WHealth — Advanced Security Suite")
        self.resize(1540, 900)
        self.setMinimumSize(1180, 720)

        # Root: sidebar + stacked pages
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # ── Sidebar ──────────────────────────────
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(14, 24, 14, 24)
        sidebar_layout.setSpacing(4)

        # Logo area
        logo_frame = QFrame()
        logo_frame.setObjectName("logoFrame")
        logo_frame.setFixedHeight(64)
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(8, 0, 0, 0)

        shield = QLabel("◆")
        shield.setStyleSheet(f"font-size: 28px; color: {RED_ACCENT}; background: transparent;")

        logo_text = QVBoxLayout()
        app_name = QLabel("WHealth")
        app_name.setStyleSheet(
            f"font-size: 18px; font-weight: 800; color: {WHITE}; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        app_sub = QLabel("Security Suite")
        app_sub.setStyleSheet(f"font-size: 10px; color: #C9A09D; background: transparent;")

        logo_text.addWidget(app_name)
        logo_text.addWidget(app_sub)
        logo_text.setSpacing(0)

        logo_layout.addWidget(shield)
        logo_layout.addSpacing(8)
        logo_layout.addLayout(logo_text)
        logo_layout.addStretch(1)

        sidebar_layout.addWidget(logo_frame)
        sidebar_layout.addSpacing(20)

        # Nav items
        self._nav_buttons: list[SidebarButton] = []
        self._pages = QStackedWidget()

        nav_items = [
            ("◆", "Dashboard"),
            ("◎", "Scan Center"),
            ("◇", "Network"),
            ("⚙", "System Scans"),
            ("◈", "Quarantine"),
            ("▤", "Rules & Reports"),
            ("≡", "Activity Logs"),
        ]

        for i, (icon, label) in enumerate(nav_items):
            btn = SidebarButton(icon, label)
            btn.clicked.connect(lambda _, idx=i: self._switch_page(idx))
            self._nav_buttons.append(btn)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch(1)

        # Bottom info
        version_label = QLabel("v2.0  ·  Professional")
        version_label.setStyleSheet(
            f"font-size: 10px; color: #6B3A38; background: transparent; "
            "text-align: center;"
        )
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(version_label)

        # ── Page area ────────────────────────────
        page_area = QWidget()
        page_area.setObjectName("pageArea")
        page_area_layout = QVBoxLayout(page_area)
        page_area_layout.setContentsMargins(0, 0, 0, 0)
        page_area_layout.setSpacing(0)

        # Top bar
        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(56)
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(24, 0, 24, 0)

        self._page_title = QLabel("Dashboard")
        self._page_title.setObjectName("pageTitle")

        topbar_layout.addWidget(self._page_title)
        topbar_layout.addStretch(1)

        # Quick action: refresh
        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setObjectName("topbarBtn")
        refresh_btn.clicked.connect(self.refresh_all)
        topbar_layout.addWidget(refresh_btn)

        reports_btn = QPushButton("▣  Reports")
        reports_btn.setObjectName("topbarBtn")
        reports_btn.clicked.connect(lambda: self.open_path(str(REPORTS_DIR)))
        topbar_layout.addWidget(reports_btn)

        page_area_layout.addWidget(topbar)
        page_area_layout.addWidget(self._pages)

        root_layout.addWidget(self.sidebar)
        root_layout.addWidget(page_area)

        # ── Build pages ───────────────────────────
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)

        self._build_dashboard_page()
        self._build_scan_page()
        self._build_network_page()
        self._build_system_page()
        self._build_quarantine_page()
        self._build_rules_page()
        self._build_logs_page()

        self._switch_page(0)
        self.apply_style()
        self.build_menu()
        self.refresh_all()
        self.statusBar().showMessage("WHealth is ready")

    # ─────────────────────────────────────────
    #  NAVIGATION
    # ─────────────────────────────────────────

    _page_titles = [
        "Dashboard",
        "Scan Center",
        "Network Audit",
        "System Scans",
        "Quarantine Manager",
        "Rules & Reports",
        "Activity Logs",
    ]

    def _switch_page(self, index: int):
        self._pages.setCurrentIndex(index)
        self._page_title.setText(self._page_titles[index])
        for i, btn in enumerate(self._nav_buttons):
            btn.set_active(i == index)

    def _make_page(self) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        page.setObjectName("pageWidget")
        scroll_content = QWidget()
        scroll_content.setObjectName("scrollContent")
        inner = QVBoxLayout(scroll_content)
        inner.setContentsMargins(24, 20, 24, 20)
        inner.setSpacing(16)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("mainScroll")

        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._pages.addWidget(page)
        return page, inner

    def _panel(self, title: str = "", parent=None) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame(parent)
        frame.setObjectName("panel")

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(22)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(15, 23, 42, 18))
        frame.setGraphicsEffect(shadow)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)
        if title:
            lbl = SectionHeader(title)
            layout.addWidget(lbl)
        return frame, layout

    # ─────────────────────────────────────────
    #  STYLE SHEET
    # ─────────────────────────────────────────

    def apply_style(self):
        self.setStyleSheet(f"""
            /* ─── Root ─── */
            QMainWindow, QWidget#pageArea, QWidget#pageWidget, QWidget#scrollContent {{
                background: {GRAY_50};
                font-family: {FONT_STACK};
            }}

            QScrollArea, QScrollArea > QWidget > QWidget {{
                background: {GRAY_50};
                border: none;
            }}

            /* ─── Sidebar ─── */
            QFrame#sidebar {{
                background: {SIDEBAR_BG};
                border: none;
            }}
            QFrame#logoFrame {{
                background: transparent;
                border: none;
            }}

            /* ─── Top bar ─── */
            QFrame#topbar {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {WHITE}, stop:1 {RED_SOFT});
                border-bottom: 1px solid {GRAY_200};
            }}
            QLabel#pageTitle {{
                font-size: 18px;
                font-weight: 800;
                color: {GRAY_900};
                font-family: {FONT_STACK};
                background: transparent;
            }}
            QPushButton#topbarBtn {{
                background: {GRAY_100};
                color: {GRAY_700};
                border: 1px solid {GRAY_300};
                border-radius: 8px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton#topbarBtn:hover {{
                background: {RED_SOFT};
                color: {RED_PRIMARY};
                border-color: {RED_LIGHT};
            }}

            /* ─── Panels ─── */
            QFrame#panel {{
                background: {WHITE};
                border: 1px solid rgba(226, 232, 240, 0.9);
                border-radius: 16px;
            }}

            /* ─── Stat cards ─── */
            QFrame#statCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {WHITE}, stop:1 {GRAY_50});
                border: 1px solid rgba(226, 232, 240, 0.92);
                border-radius: 16px;
            }}
            QFrame#statCard:hover {{
                border: 1px solid {RED_BORDER};
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {WHITE}, stop:1 {RED_SOFT});
            }}

            /* ─── Section title ─── */
            QLabel#panelTitle {{
                font-size: 14px;
                font-weight: 800;
                color: {GRAY_900};
                letter-spacing: 0.3px;
                background: transparent;
                font-family: {FONT_STACK};
            }}

            /* ─── Protection widget ─── */
            QFrame#protectionWidget {{
                background: {WHITE};
                border: 1px solid {GRAY_200};
                border-radius: 14px;
            }}

            /* ─── Security summary card ─── */
            QFrame#securityCard {{
                background: {WHITE};
                border: 1px solid {GRAY_200};
                border-radius: 14px;
                overflow: hidden;
            }}
            QFrame#securityCardHeader {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {RED_PRIMARY}, stop:1 {RED_DARK});
                border-radius: 0;
                border-top-left-radius: 14px;
                border-top-right-radius: 14px;
            }}
            QTextEdit#securityCardContent {{
                background: {WHITE};
                border: none;
                border-bottom-left-radius: 14px;
                border-bottom-right-radius: 14px;
                padding: 14px;
                font-family: {FONT_STACK};
                font-size: 13px;
                color: {GRAY_700};
                selection-background-color: {RED_LIGHT};
            }}

            /* ─── Buttons ─── */
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {RED_ACCENT}, stop:0.55 {RED_PRIMARY}, stop:1 {RED_DARK});
                color: {WHITE};
                border: 1px solid rgba(255, 255, 255, 0.18);
                border-radius: 10px;
                padding: 10px 18px;
                font-weight: 800;
                font-size: 12px;
                letter-spacing: 0.2px;
                font-family: {FONT_STACK};
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FF6372, stop:0.45 {RED_PRIMARY}, stop:1 {RED_DEEPER});
            }}
            QPushButton:disabled {{
                background: {GRAY_300};
                color: {GRAY_500};
            }}
            QPushButton#secondary {{
                background: {WHITE};
                color: {RED_PRIMARY};
                border: 1.5px solid {RED_LIGHT};
            }}
            QPushButton#secondary:hover {{
                background: {RED_SOFT};
                border-color: {RED_PRIMARY};
            }}
            QPushButton#danger {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FF4D5E, stop:0.5 #D7263D, stop:1 #8F1227);
            }}
            QPushButton#danger:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #D7263D, stop:1 #6E0F1D);
            }}

            /* ─── Input ─── */
            QLineEdit {{
                background: {WHITE};
                border: 1.5px solid {GRAY_300};
                border-radius: 8px;
                padding: 8px 12px;
                font-size: 12px;
                color: {GRAY_900};
                selection-background-color: {RED_LIGHT};
            }}
            QLineEdit:focus {{
                border-color: {RED_PRIMARY};
            }}

            /* ─── Tables ─── */
            QTableWidget {{
                background: {WHITE};
                border: 1px solid {TABLE_BORDER};
                border-radius: 14px;
                gridline-color: transparent;
                selection-background-color: {TABLE_SELECTED};
                selection-color: {WHITE};
                font-size: 12px;
                font-family: {FONT_STACK};
                outline: 0;
                alternate-background-color: {TABLE_ALT};
            }}
            QTableWidget::item {{
                padding: 10px 12px;
                border: none;
                border-bottom: 1px solid rgba(226, 232, 240, 0.70);
            }}
            QTableWidget::item:hover {{
                background: {TABLE_HOVER};
                color: {GRAY_900};
            }}
            QTableWidget::item:selected {{
                background: {TABLE_SELECTED};
                color: {WHITE};
            }}
            QHeaderView::section {{
                background: {TABLE_HEADER};
                color: {WHITE};
                font-weight: 800;
                font-size: 11px;
                letter-spacing: 0.8px;
                text-transform: uppercase;
                padding: 12px 10px;
                border: none;
                border-right: 1px solid rgba(255, 255, 255, 0.16);
                border-bottom: 1px solid {RED_DEEPER};
            }}
            QHeaderView::section:hover {{
                background: {TABLE_HEADER_HOVER};
            }}
            QTableCornerButton::section {{
                background: {TABLE_HEADER};
                border: none;
            }}

            /* ─── Text areas ─── */
            QPlainTextEdit {{
                background: {WHITE};
                border: 1.5px solid {GRAY_200};
                border-radius: 10px;
                padding: 12px;
                font-family: {FONT_STACK};
                font-size: 13px;
                color: {GRAY_700};
                selection-background-color: {RED_LIGHT};
            }}
            QPlainTextEdit:focus {{
                border-color: {RED_LIGHT};
            }}

            /* ─── Progress bar ─── */
            QProgressBar {{
                border: none;
                border-radius: 5px;
                height: 10px;
                text-align: center;
                background: {GRAY_200};
                font-size: 10px;
                color: {GRAY_700};
            }}
            QProgressBar::chunk {{
                border-radius: 5px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {RED_ACCENT}, stop:1 {RED_PRIMARY});
            }}

            /* ─── Checkbox ─── */
            QCheckBox {{
                spacing: 8px;
                color: {GRAY_700};
                font-size: 12px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 1.5px solid {GRAY_300};
                background: {WHITE};
            }}
            QCheckBox::indicator:checked {{
                background: {RED_PRIMARY};
                border-color: {RED_PRIMARY};
            }}

            /* ─── Group box ─── */
            QGroupBox {{
                background: {WHITE};
                border: 1px solid {GRAY_200};
                border-radius: 14px;
                margin-top: 14px;
                padding-top: 26px;
                font-weight: 800;
                font-size: 13px;
                color: {GRAY_900};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 16px;
                top: 7px;
                color: {GRAY_900};
            }}

            /* ─── Scroll bars ─── */
            QScrollBar:vertical {{
                background: transparent;
                width: 6px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {GRAY_300};
                border-radius: 3px;
                min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background: {GRAY_300};
                border-radius: 3px;
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}

            /* ─── Status bar ─── */
            QStatusBar {{
                background: {WHITE};
                border-top: 1px solid {GRAY_200};
                color: {GRAY_700};
                font-size: 11px;
                padding: 4px 16px;
            }}

            /* ─── Splitter ─── */
            QSplitter::handle {{
                background: {GRAY_200};
                width: 1px;
                height: 1px;
            }}
        """)

    def build_menu(self):
        menu = self.menuBar()
        menu.setStyleSheet(
            f"QMenuBar {{ background: {WHITE}; color: {GRAY_900}; font-size: 12px; }}"
            f"QMenuBar::item:selected {{ background: {RED_SOFT}; color: {RED_PRIMARY}; }}"
            f"QMenu {{ background: {WHITE}; border: 1px solid {GRAY_200}; }}"
            f"QMenu::item:selected {{ background: {RED_SOFT}; color: {RED_PRIMARY}; }}"
        )
        app_menu = menu.addMenu("WHealth")

        for label, callback in [
            ("Refresh", self.refresh_all),
            ("Open Reports Folder", lambda: self.open_path(str(REPORTS_DIR))),
            ("Exit", self.close),
        ]:
            action = QAction(label, self)
            action.triggered.connect(callback)
            app_menu.addAction(action)

    # ─────────────────────────────────────────
    #  TABLE HELPERS
    # ─────────────────────────────────────────

    def setup_table(self, table: QTableWidget):
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setSortingEnabled(True)
        table.setWordWrap(False)
        table.setMouseTracking(True)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(42)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setMinimumHeight(44)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setShowGrid(False)
        table.setFrameShape(QFrame.Shape.NoFrame)

    def item(self, value: Any, bold: bool = False, center: bool = False,
             fg: QColor | None = None, bg: QColor | None = None) -> QTableWidgetItem:
        text_value = str(value if value is not None else "")
        it = QTableWidgetItem(text_value)
        it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)

        font = it.font()
        font.setFamily(UI_FONT_QT)
        font.setPointSize(10)
        font.setWeight(QFont.Weight.DemiBold if bold else QFont.Weight.Medium)
        it.setFont(font)
        it.setToolTip(text_value)

        if center:
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            it.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        it.setForeground(fg or QColor(GRAY_700))
        it.setBackground(bg or QColor(WHITE))
        return it

    def verdict_colors(self, verdict: str):
        verdict = (verdict or "").lower()
        if verdict == "clean":
            return QColor(GREEN_LIGHT), QColor(GREEN_OK)
        if verdict == "review needed":
            return QColor(AMBER_LIGHT), QColor(AMBER_WARN)
        if verdict in {"malicious", "high risk", "high-risk malware"}:
            return QColor(RED_LIGHT), QColor(RED_DARK)
        return QColor(GRAY_100), QColor(GRAY_700)

    def risk_colors(self, risk: int):
        risk = int(risk or 0)
        if risk >= 70:
            return QColor(RED_LIGHT), QColor(RED_DARK)
        if risk >= 40:
            return QColor(AMBER_LIGHT), QColor(AMBER_WARN)
        return QColor(GREEN_LIGHT), QColor(GREEN_OK)

    def neutral_row_bg(self, row: int):
        return QColor(TABLE_ALT if row % 2 else WHITE)

    # ─────────────────────────────────────────
    #  PAGE: DASHBOARD
    # ─────────────────────────────────────────

    def _build_dashboard_page(self):
        _, layout = self._make_page()

        # ── Stat cards row ──
        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        self.cards = {}
        card_defs = [
            ("all",        "Total Scanned",  GRAY_700,    "●"),
            ("clean",      "Trusted",        GREEN_OK,    "✓"),
            ("review",     "Need Review",    AMBER_WARN,  "!"),
            ("malicious",  "High Risk",      RED_PRIMARY, "×"),
            ("quarantined","Quarantined",    GRAY_700,    "■"),
        ]
        for key, title, color, icon in card_defs:
            card = StatCard(key, title, "0", color, icon)
            card.clicked.connect(self.set_dashboard_filter)
            self.cards[key] = card
            cards_row.addWidget(card)

        layout.addLayout(cards_row)

        # ── Middle row: donut + protection status ──
        mid = QHBoxLayout()
        mid.setSpacing(14)

        # Donut chart panel
        chart_panel, chart_layout = self._panel("Scan Distribution")
        chart_layout.setSpacing(8)

        self.donut = DonutChart()
        self.donut.setMinimumHeight(220)
        self.donut.clicked.connect(self.set_dashboard_filter)

        self.dashboard_summary = QLabel(
            "Click a card or chart segment to filter the scan history below."
        )
        self.dashboard_summary.setWordWrap(True)
        self.dashboard_summary.setStyleSheet(
            f"font-size: 11px; color: {GRAY_500}; background: transparent;"
        )

        chart_layout.addWidget(self.donut)
        chart_layout.addWidget(self.dashboard_summary)

        # Protection status
        self.protection_widget = ProtectionStatusWidget()

        mid.addWidget(chart_panel, 3)
        mid.addWidget(self.protection_widget, 2)
        layout.addLayout(mid)

        # ── Friendly guidance strip ──
        model_strip, model_layout = self._panel()
        model_layout.setContentsMargins(16, 10, 16, 10)
        model_layout.setSpacing(0)

        self.model_status_label = QLabel("Ready when you are. Start with Scan Center to check a file or folder.")
        self.model_status_label.setStyleSheet(
            f"font-size: 12px; color: {GRAY_700}; background: transparent;"
        )
        model_layout.addWidget(self.model_status_label)
        layout.addWidget(model_strip)

        # ── Scan history table ──
        history_panel, history_layout = self._panel("Recent Scan History")

        filter_row = QHBoxLayout()
        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet(f"font-size: 12px; color: {GRAY_500}; background: transparent;")
        filter_row.addWidget(filter_lbl)

        self._dash_filter_input = QLineEdit()
        self._dash_filter_input.setPlaceholderText("Search by file name, verdict, threat insight...")
        self._dash_filter_input.textChanged.connect(self._apply_history_filter)
        filter_row.addWidget(self._dash_filter_input, 1)

        history_layout.addLayout(filter_row)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "Time", "Verdict", "Trust / Risk", "Threat Insight",
            "Quarantined", "File", "Path",
        ])
        self.setup_table(self.history_table)
        self.history_table.setColumnWidth(0, 150)
        self.history_table.setColumnWidth(1, 120)
        self.history_table.setColumnWidth(2, 150)
        self.history_table.setColumnWidth(3, 220)
        self.history_table.setColumnWidth(4, 100)
        self.history_table.setColumnWidth(5, 200)

        history_layout.addWidget(self.history_table)
        layout.addWidget(history_panel, 1)

    def _apply_history_filter(self):
        text = self._dash_filter_input.text().lower().strip()
        for row in range(self.history_table.rowCount()):
            row_text = " ".join(
                self.history_table.item(row, col).text().lower()
                for col in range(self.history_table.columnCount())
                if self.history_table.item(row, col)
            )
            self.history_table.setRowHidden(row, bool(text and text not in row_text))

    def set_dashboard_filter(self, key: str):
        self.dashboard_filter = "all" if self.dashboard_filter == key else key
        self.refresh_dashboard()

    # ─────────────────────────────────────────
    #  PAGE: SCAN CENTER
    # ─────────────────────────────────────────

    def _build_scan_page(self):
        _, layout = self._make_page()

        # Target panel
        target_panel, target_layout = self._panel("Scan Target")

        path_row = QHBoxLayout()
        self.scan_path = QLineEdit(str(SCAN_TARGETS_DIR))
        path_row.addWidget(self.scan_path, 1)

        choose_file = QPushButton("□  File")
        choose_file.setObjectName("secondary")
        choose_file.clicked.connect(self.choose_scan_file)

        choose_folder = QPushButton("▣  Folder")
        choose_folder.setObjectName("secondary")
        choose_folder.clicked.connect(self.choose_scan_folder)

        path_row.addWidget(choose_file)
        path_row.addWidget(choose_folder)
        target_layout.addLayout(path_row)

        self.quarantine_check = QCheckBox(
            "Auto-quarantine files marked as malicious or high risk"
        )
        target_layout.addWidget(self.quarantine_check)

        scan_tip = QLabel(
            "Tip: Scan downloads, USB drives, and unknown folders before opening files. "
            "Reports are saved automatically after each scan."
        )
        scan_tip.setWordWrap(True)
        scan_tip.setStyleSheet(f"font-size: 12px; color: {GRAY_500}; background: transparent;")
        target_layout.addWidget(scan_tip)

        btn_row = QHBoxLayout()
        self.scan_button = QPushButton("▶  Start Scan")
        self.scan_button.clicked.connect(self.start_scan)

        self.open_html_button = QPushButton("◇  HTML Report")
        self.open_html_button.setObjectName("secondary")
        self.open_html_button.clicked.connect(lambda: self.open_path(self.last_html_report))
        self.open_html_button.setEnabled(False)

        self.open_pdf_button = QPushButton("□  PDF Report")
        self.open_pdf_button.setObjectName("secondary")
        self.open_pdf_button.clicked.connect(lambda: self.open_path(self.last_pdf_report))
        self.open_pdf_button.setEnabled(False)

        btn_row.addWidget(self.scan_button)
        btn_row.addWidget(self.open_html_button)
        btn_row.addWidget(self.open_pdf_button)
        btn_row.addStretch(1)
        target_layout.addLayout(btn_row)

        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.hide()
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet(f"font-size: 12px; color: {GRAY_700}; background: transparent;")
        self.scan_status.hide()
        target_layout.addWidget(self.scan_progress)
        target_layout.addWidget(self.scan_status)

        layout.addWidget(target_panel)

        # Results split
        split = QSplitter(Qt.Orientation.Horizontal)

        left_panel, left_layout = self._panel("Scan Results")
        left_panel.setObjectName("panel")

        filter_row = QHBoxLayout()
        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet(f"font-size: 12px; color: {GRAY_500}; background: transparent;")
        filter_row.addWidget(filter_lbl)
        self.scan_filter = QLineEdit()
        self.scan_filter.setPlaceholderText("File, verdict, finding, threat insight...")
        self.scan_filter.textChanged.connect(self.apply_scan_filter)
        filter_row.addWidget(self.scan_filter, 1)
        left_layout.addLayout(filter_row)

        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(8)
        self.scan_table.setHorizontalHeaderLabels([
            "Verdict", "Trust / Risk", "Threat Insight", "Confidence",
            "Main Finding", "Quarantine", "File", "Path",
        ])
        self.setup_table(self.scan_table)
        self.scan_table.setColumnWidth(0, 110)
        self.scan_table.setColumnWidth(1, 140)
        self.scan_table.setColumnWidth(2, 210)
        self.scan_table.setColumnWidth(3, 95)
        self.scan_table.setColumnWidth(4, 240)
        self.scan_table.setColumnWidth(5, 95)
        self.scan_table.setColumnWidth(6, 200)
        self.scan_table.itemSelectionChanged.connect(self.show_selected_scan_detail)
        left_layout.addWidget(self.scan_table)

        right_panel, right_layout = self._panel("Selected File — Security Details")
        self.scan_detail_card = SecuritySummaryCard("File Detail & Findings")
        right_layout.addWidget(self.scan_detail_card)

        split.addWidget(left_panel)
        split.addWidget(right_panel)
        split.setSizes([960, 440])
        layout.addWidget(split, 1)

    # ─────────────────────────────────────────
    #  PAGE: NETWORK
    # ─────────────────────────────────────────

    def _build_network_page(self):
        _, layout = self._make_page()

        ctrl_panel, ctrl_layout = self._panel("Network Audit Controls")

        info = QLabel(
            "Reads active OS connections (PID, process, local/remote address, port, status), "
            "then takes a short traffic sample to highlight unusual network behavior. "
            "This check does not change firewall settings. Packet capture may require Npcap and administrator rights on Windows."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"font-size: 12px; color: {GRAY_500}; background: transparent;")

        btn_row = QHBoxLayout()
        self.network_button = QPushButton("◇  Run Network Safety Check")
        self.network_button.clicked.connect(lambda: self.start_action("network"))

        self.network_progress = QProgressBar()
        self.network_progress.setRange(0, 100)
        self.network_progress.hide()

        btn_row.addWidget(self.network_button)
        btn_row.addStretch(1)
        btn_row.addWidget(self.network_progress)
        ctrl_layout.addWidget(info)
        ctrl_layout.addLayout(btn_row)
        layout.addWidget(ctrl_panel)

        split = QSplitter(Qt.Orientation.Horizontal)

        left_panel, left_layout = self._panel("Active Network Connections")
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(11)
        self.network_table.setHorizontalHeaderLabels([
            "Risk", "PID", "Process", "Protocol", "Status",
            "Local Addr", "Local Port", "Remote Addr", "Remote Port",
            "Process Path", "Reason",
        ])
        self.setup_table(self.network_table)
        for i, w in enumerate([70, 70, 160, 75, 90, 140, 85, 150, 85, 280, 400]):
            self.network_table.setColumnWidth(i, w)
        left_layout.addWidget(self.network_table)

        right_panel, right_layout = self._panel("Network Safety Summary")
        self.network_summary_card = SecuritySummaryCard("Network Security Report")
        right_layout.addWidget(self.network_summary_card)

        split.addWidget(left_panel)
        split.addWidget(right_panel)
        split.setSizes([1020, 460])
        layout.addWidget(split, 1)

    # ─────────────────────────────────────────
    #  PAGE: SYSTEM SCANS
    # ─────────────────────────────────────────

    def _build_system_page(self):
        _, layout = self._make_page()

        ctrl_panel, ctrl_layout = self._panel("System Scan Tasks")

        task_grid = QGridLayout()
        task_grid.setSpacing(10)

        tasks = [
            ("◆  USB Drive Scan",          "usb",     "Scan removable drives for threats"),
            ("◆  Startup Items",           "startup", "Audit startup entry points"),
            ("◆  Scheduled Tasks",         "tasks",   "Review all scheduled task entries"),
            ("◆  Process Behavior",        "process", "Analyze running process behavior"),
            ("◆  Memory & Process Risk",   "memory",  "Deep memory and process risk scan"),
        ]

        for i, (title, action, hint) in enumerate(tasks):
            col = i % 3
            row_idx = i // 3
            btn = QPushButton(title)
            btn.setFixedHeight(52)
            btn.clicked.connect(lambda _, a=action: self.start_action(a))
            task_grid.addWidget(btn, row_idx, col)

        ctrl_layout.addLayout(task_grid)

        self.system_progress = QProgressBar()
        self.system_progress.setRange(0, 100)
        self.system_progress.hide()
        ctrl_layout.addWidget(self.system_progress)

        layout.addWidget(ctrl_panel)

        split = QSplitter(Qt.Orientation.Horizontal)

        left_panel, left_layout = self._panel("System Findings")
        self.system_events_table = QTableWidget()
        self.system_events_table.setColumnCount(7)
        self.system_events_table.setHorizontalHeaderLabels([
            "Status", "Type", "Name", "PID / Path", "Risk", "Source", "Details",
        ])
        self.setup_table(self.system_events_table)
        for i, w in enumerate([95, 130, 210, 260, 75, 140, 520]):
            self.system_events_table.setColumnWidth(i, w)
        left_layout.addWidget(self.system_events_table)

        right_panel, right_layout = self._panel("Task Summary & Guidance")
        self.system_summary_card = SecuritySummaryCard("System Scan Summary")
        right_layout.addWidget(self.system_summary_card)

        split.addWidget(left_panel)
        split.addWidget(right_panel)
        split.setSizes([860, 500])
        layout.addWidget(split, 1)

    # ─────────────────────────────────────────
    #  PAGE: QUARANTINE
    # ─────────────────────────────────────────

    def _build_quarantine_page(self):
        _, layout = self._make_page()

        info_panel, info_layout = self._panel()
        info_layout.setContentsMargins(16, 12, 16, 12)

        info_text = QLabel(
            "◆  Files moved here are isolated from their original location. "
            "Only restore a file if you are certain it is safe."
        )
        info_text.setWordWrap(True)
        info_text.setStyleSheet(
            f"font-size: 13px; color: {GRAY_700}; background: transparent;"
        )

        btn_row = QHBoxLayout()

        refresh = QPushButton("↻  Refresh")
        refresh.clicked.connect(self.refresh_quarantine)

        restore = QPushButton("↩  Restore Selected")
        restore.setObjectName("secondary")
        restore.clicked.connect(self.restore_selected_quarantine)

        delete = QPushButton("×  Delete Selected")
        delete.setObjectName("danger")
        delete.clicked.connect(self.delete_selected_quarantine)

        openq = QPushButton("▣  Open Folder")
        openq.setObjectName("secondary")
        openq.clicked.connect(lambda: self.open_path(str(QUARANTINE_DIR)))

        btn_row.addWidget(refresh)
        btn_row.addWidget(restore)
        btn_row.addWidget(delete)
        btn_row.addWidget(openq)
        btn_row.addStretch(1)

        info_layout.addWidget(info_text)
        info_layout.addLayout(btn_row)
        layout.addWidget(info_panel)

        table_panel, table_layout = self._panel("Quarantined Files")
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "File", "Original Path", "SHA-256", "Size", "Quarantine Path",
        ])
        self.setup_table(self.quarantine_table)
        for i, w in enumerate([210, 340, 240, 90, 400]):
            self.quarantine_table.setColumnWidth(i, w)
        table_layout.addWidget(self.quarantine_table)
        layout.addWidget(table_panel, 1)

    # ─────────────────────────────────────────
    #  PAGE: RULES & REPORTS
    # ─────────────────────────────────────────

    def _build_rules_page(self):
        _, layout = self._make_page()

        ctrl_panel, ctrl_layout = self._panel("YARA Rule Management")

        btn_row = QHBoxLayout()
        refresh = QPushButton("↻  Refresh Rules")
        refresh.clicked.connect(self.refresh_rules)

        validate = QPushButton("✓  Validate Selected")
        validate.setObjectName("secondary")
        validate.clicked.connect(self.validate_selected_rule)

        reports = QPushButton("▣  Reports Folder")
        reports.setObjectName("secondary")
        reports.clicked.connect(lambda: self.open_path(str(REPORTS_DIR)))

        btn_row.addWidget(refresh)
        btn_row.addWidget(validate)
        btn_row.addWidget(reports)
        btn_row.addStretch(1)
        ctrl_layout.addLayout(btn_row)
        layout.addWidget(ctrl_panel)

        split = QSplitter(Qt.Orientation.Horizontal)

        left_panel, left_layout = self._panel("YARA Rule Files")
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(3)
        self.rules_table.setHorizontalHeaderLabels(["Rule File", "Size (bytes)", "Full Path"])
        self.setup_table(self.rules_table)
        self.rules_table.setColumnWidth(0, 210)
        self.rules_table.setColumnWidth(1, 90)
        left_layout.addWidget(self.rules_table)

        right_panel, right_layout = self._panel("Validation Output")
        self.rules_summary_card = SecuritySummaryCard("Rule Validation")
        right_layout.addWidget(self.rules_summary_card)

        split.addWidget(left_panel)
        split.addWidget(right_panel)
        split.setSizes([620, 620])
        layout.addWidget(split, 1)

    # ─────────────────────────────────────────
    #  PAGE: LOGS
    # ─────────────────────────────────────────

    def _build_logs_page(self):
        _, layout = self._make_page()

        ctrl_panel, ctrl_layout = self._panel()
        ctrl_layout.setContentsMargins(12, 10, 12, 10)

        info = QLabel("Real-time activity log from all scans, reports, and security tasks.")
        info.setStyleSheet(f"font-size: 12px; color: {GRAY_500}; background: transparent;")

        clear = QPushButton("×  Clear Logs")
        clear.setObjectName("secondary")
        clear.clicked.connect(self.log_box.clear)

        row = QHBoxLayout()
        row.addWidget(info)
        row.addStretch(1)
        row.addWidget(clear)
        ctrl_layout.addLayout(row)
        layout.addWidget(ctrl_panel)

        log_panel, log_layout = self._panel("Activity Log")
        log_layout.addWidget(self.log_box)
        layout.addWidget(log_panel, 1)

    # ─────────────────────────────────────────
    #  SCAN LOGIC
    # ─────────────────────────────────────────

    def choose_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file", str(Path.home()))
        if path:
            self.scan_path.setText(path)

    def choose_scan_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose folder", str(Path.home()))
        if path:
            self.scan_path.setText(path)

    def start_scan(self):
        path = self.scan_path.text().strip()
        if not path:
            QMessageBox.warning(self, "Missing target", "Choose a file or folder to scan.")
            return
        self.scan_table.setRowCount(0)
        self.scan_detail_card.set_plain("Select a file from the results table to see detailed analysis.")
        self.scan_progress.setValue(0)
        self.scan_progress.show()
        self.scan_status.show()
        self.scan_button.setEnabled(False)
        self.log(f"Scan started: {path}")
        self.scan_worker = ScanWorker(path, self.quarantine_check.isChecked())
        self.scan_worker.progress.connect(self.on_scan_progress)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.failed.connect(self.on_scan_failed)
        self.scan_worker.start()

    def on_scan_progress(self, value: int, message: str):
        self.scan_progress.setValue(value)
        self.scan_status.setText(message)
        self.statusBar().showMessage(message)
        self.log(message)

    def on_scan_finished(self, results: list, html_report: str, pdf_report: str, explanation: str):
        self.scan_button.setEnabled(True)
        self.scan_progress.hide()
        self.scan_status.hide()
        self.last_scan_results = results
        self.last_html_report = html_report
        self.last_pdf_report = pdf_report
        self.open_html_button.setEnabled(bool(html_report))
        self.open_pdf_button.setEnabled(bool(pdf_report))
        self.populate_scan_table(results)
        self.scan_detail_card.set_plain(explanation)
        self.refresh_all()
        QMessageBox.information(self, "Scan Complete", explanation[:1200])

    def on_scan_failed(self, error: str):
        self.scan_button.setEnabled(True)
        self.scan_progress.hide()
        self.scan_status.hide()
        self.log(f"Scan failed: {error}")
        QMessageBox.critical(self, "Scan Failed", error)

    def populate_scan_table(self, results: list[dict[str, Any]]):
        self.scan_table.setSortingEnabled(False)
        self.scan_table.setRowCount(len(results))
        for row, result in enumerate(results):
            detections = result.get("detections", []) or []
            main = detections[0].get("name", "No finding") if detections else "No finding"
            bg, fg = self.verdict_colors(result.get("verdict", ""))
            values = [
                result.get("verdict"),
                result.get("trust_label"),
                result.get("model_type") or "Not applicable",
                f"{float(result.get('model_confidence', 0) or 0):.0%}",
                main,
                "Yes" if result.get("quarantined") else "No",
                Path(result.get("path", "")).name,
                result.get("path", ""),
            ]
            for col, value in enumerate(values):
                self.scan_table.setItem(row, col, self.item(
                    value, bold=col in {0, 1}, center=col in {0, 3, 5},
                    fg=fg if col in {0, 1, 3, 5} else QColor(GRAY_700),
                    bg=bg,
                ))
        self.scan_table.setSortingEnabled(True)
        self.apply_scan_filter()

    def apply_scan_filter(self):
        text = self.scan_filter.text().lower().strip() if hasattr(self, "scan_filter") else ""
        for row in range(self.scan_table.rowCount()):
            row_text = " ".join(
                self.scan_table.item(row, col).text().lower()
                for col in range(self.scan_table.columnCount())
                if self.scan_table.item(row, col)
            )
            self.scan_table.setRowHidden(row, bool(text and text not in row_text))

    def show_selected_scan_detail(self):
        rows = self.scan_table.selectionModel().selectedRows() if self.scan_table.selectionModel() else []
        if not rows:
            return
        path_item = self.scan_table.item(rows[0].row(), 7)
        if not path_item:
            return
        path = path_item.text()
        result = next((r for r in self.last_scan_results if r.get("path") == path), None)
        if not result:
            return

        lines = [
            f"File: {Path(path).name}",
            f"Path: {path}",
            "",
            "Verdict:",
            f"- {result.get('verdict')}",
            "",
            "Trust & Risk:",
            f"- {result.get('trust_label')}",
            "",
            "Automated Security Check:",
            "- Method: Local file reputation and behavior checks",
            f"- Result: {result.get('model_type') or 'No automated result'}",
            f"- Confidence: {float(result.get('model_confidence', 0) or 0):.0%}",
            "",
            "File Identity:",
            f"- SHA-256: {result.get('sha256')}",
            "",
            "Findings:",
        ]

        for detection in result.get("detections", []) or []:
            engine = detection.get("engine") or detection.get("detector") or "Scanner"
            lines.append(
                f"- {engine}: {detection.get('name')} "
                f"({detection.get('severity')}/100). {detection.get('details')}"
            )
        if not result.get("detections"):
            lines.append("- No suspicious finding detected.")

        self.scan_detail_card.set_plain("\n".join(lines))

    # ─────────────────────────────────────────
    #  ACTION LOGIC
    # ─────────────────────────────────────────

    def start_action(self, action: str):
        progress = self.network_progress if action == "network" else self.system_progress
        progress.setValue(0)
        progress.show()
        if action == "network":
            self.network_button.setEnabled(False)
        self.action_worker = ActionWorker(action)
        self.action_worker.progress.connect(
            lambda value, message, p=progress: (
                p.setValue(value),
                self.statusBar().showMessage(message),
                self.log(message),
            )
        )
        self.action_worker.finished.connect(self.on_action_finished)
        self.action_worker.failed.connect(self.on_action_failed)
        self.action_worker.start()

    def on_action_failed(self, error: str):
        self.network_progress.hide()
        self.system_progress.hide()
        if hasattr(self, "network_button"):
            self.network_button.setEnabled(True)
        self.log(f"Task failed: {error}")
        QMessageBox.critical(self, "Task Failed", error)

    def on_action_finished(self, action: str, result: object):
        self.network_progress.hide()
        self.system_progress.hide()
        if hasattr(self, "network_button"):
            self.network_button.setEnabled(True)
        self.log(f"{action} finished")
        if action == "network":
            self.show_network_result(result)
            self.refresh_all()
        else:
            self.show_system_result(result)
            self.refresh_dashboard()
            self.refresh_quarantine()
            self.refresh_rules()

    def show_network_result(self, result: dict[str, Any]):
        if not result.get("ok"):
            self.network_table.setRowCount(0)
            self.network_summary_card.set_plain(
                f"Network Audit Failed:\n\n{result.get('error', 'Unknown error')}"
            )
            return

        connections = result.get("connections", []) or []
        findings = result.get("findings", []) or []
        summary = result.get("summary", {}) or {}

        self.network_table.setSortingEnabled(False)
        self.network_table.setRowCount(len(connections))

        for row, conn in enumerate(connections):
            risk = int(conn.get("risk", 0) or 0)
            bg, fg = self.risk_colors(risk)
            values = [
                risk, conn.get("pid", ""), conn.get("process_name", ""),
                conn.get("protocol", ""), conn.get("status", ""),
                conn.get("local_address", ""), conn.get("local_port", ""),
                conn.get("remote_address", ""), conn.get("remote_port", ""),
                conn.get("process_path", ""), conn.get("reason", ""),
            ]
            for col, value in enumerate(values):
                bold = col in {0, 2, 4}
                center = col in {0, 1, 3, 4, 6, 8}
                self.network_table.setItem(
                    row,
                    col,
                    self.item(
                        value,
                        bold=bold,
                        center=center,
                        fg=fg if col in {0, 2, 4, 10} else QColor(GRAY_700),
                        bg=bg,
                    ),
                )

        self.network_table.setSortingEnabled(True)

        # Build user-friendly network summary text
        ai_report = str(result.get("ai_report", "") or "").strip()
        cicids = result.get("cicids_ai", {}) or {}
        flow_capture = result.get("flow_capture", {}) or {}

        text = []

        if ai_report:
            text.append(ai_report)
        else:
            text.append(format_network_report_for_user(result))

        text.append("")
        text.append("Network Summary:")
        text.append(f"- Total connections: {summary.get('total_connections', len(connections))}")
        text.append(f"- External connections: {summary.get('external_connections', 0)}")
        text.append(f"- Listening services: {summary.get('listening_services', 0)}")
        text.append(f"- Suspicious findings: {summary.get('suspicious_findings', len(findings))}")
        text.append(f"- Highest risk score: {summary.get('highest_risk', 0)} / 100")

        text.append("")
        text.append("Traffic Pattern Review:")
        text.append(
            f"- Flows captured: {flow_capture.get('flow_count', 0)}  "
            f"({flow_capture.get('packet_count', 0)} packets)"
        )
        if flow_capture.get("ok"):
            text.append("- Traffic sample: Ready")
        else:
            text.append(f"- Traffic sample: {flow_capture.get('error', 'Not available')}")

        if cicids.get("ran"):
            text.append("- Pattern check: Completed")
            text.append(str(cicids.get("summary", "")))
            predictions = cicids.get("predictions", []) or []
            if predictions:
                text.append("")
                text.append("Traffic Pattern Findings:")
                for pred in predictions[:20]:
                    confidence = float(pred.get("confidence", 0.0) or 0.0)
                    text.append(
                        f"- Flow {pred.get('flow_index')}: {pred.get('prediction')} "
                        f"(confidence {confidence:.0%})"
                    )
        else:
            text.append("- Pattern check: Not available")
            text.append(str(cicids.get("summary", "No summary available.")))

        if findings:
            text.append("")
            text.append("Flagged Connections:")
            for finding in findings[:50]:
                text.append(
                    f"- {finding.get('process_name', 'Unknown')} (PID {finding.get('pid', '')}) "
                    f"→ {finding.get('remote_address', '')}:{finding.get('remote_port', '')}  "
                    f"Risk: {finding.get('severity', 0)}/100"
                )
                text.append(f"  Reason: {finding.get('reason', '')}")
        else:
            text.append("")
            text.append("- No risky network connections detected by local rule checks.")

        self.network_summary_card.set_plain("\n".join(text))

    def _system_status_style(self, status: str, risk: int = 0):
        status_l = (status or "").lower()

        if risk >= 70 or "finding" in status_l or "risky" in status_l or "suspicious" in status_l:
            return QColor(RED_LIGHT), QColor(RED_DARK)

        if risk >= 40 or "review" in status_l:
            return QColor(AMBER_LIGHT), QColor(AMBER_WARN)

        if "unavailable" in status_l or "error" in status_l:
            return QColor(GRAY_100), QColor(GRAY_700)

        return QColor(GREEN_LIGHT), QColor(GREEN_OK)

    def _event_to_system_row(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "Finding" if int(event.get("severity") or 0) > 0 else "Checked",
            "type": event.get("category") or "System event",
            "name": event.get("title") or "System finding",
            "pid": "",
            "path": event.get("path") or "",
            "risk": int(event.get("severity") or 0),
            "source": event.get("source") or "SystemScanner",
            "details": event.get("details") or "",
        }

    def _populate_system_table_from_rows(self, rows: list[dict[str, Any]]):
        self.system_events_table.setSortingEnabled(False)
        self.system_events_table.setRowCount(len(rows))

        for row_idx, row in enumerate(rows):
            status = row.get("status", "Checked")
            risk = int(row.get("risk", 0) or 0)
            bg, fg = self._system_status_style(status, risk)

            pid_path = row.get("pid") or row.get("path") or ""

            values = [
                status,
                row.get("type", ""),
                row.get("name", ""),
                pid_path,
                risk,
                row.get("source", ""),
                row.get("details", ""),
            ]

            for col, value in enumerate(values):
                self.system_events_table.setItem(
                    row_idx,
                    col,
                    self.item(
                        value,
                        bold=col in {0, 2, 4},
                        center=col in {0, 4},
                        fg=fg if col in {0, 2, 4} else QColor(GRAY_700),
                        bg=bg,
                    ),
                )

        self.system_events_table.setSortingEnabled(True)

    def show_system_result(self, result: dict[str, Any]):
        if not isinstance(result, dict):
            result = {"summary": str(result), "events": [], "checked_items": []}

        events = result.get("events", []) or []
        checked_items = result.get("checked_items", []) or []

        rows: list[dict[str, Any]] = []

        for event in events:
            rows.append(self._event_to_system_row(event))

        for item in checked_items:
            rows.append(
                {
                    "status": item.get("status", "Checked"),
                    "type": item.get("type", "Checked item"),
                    "name": item.get("name", ""),
                    "pid": item.get("pid", ""),
                    "path": item.get("path", ""),
                    "risk": int(item.get("risk", 0) or 0),
                    "source": item.get("source", "SystemInventory"),
                    "details": item.get("details", ""),
                }
            )

        if not rows:
            rows.append(
                {
                    "status": "Checked",
                    "type": "System scan",
                    "name": "No item list returned",
                    "pid": "",
                    "path": "",
                    "risk": 0,
                    "source": "SystemScanner",
                    "details": "The task completed, but it did not return checked items.",
                }
            )

        rows.sort(key=lambda r: int(r.get("risk", 0) or 0), reverse=True)
        self._populate_system_table_from_rows(rows)

        checked_count = len(checked_items)
        finding_count = len(events)
        high_count = sum(1 for e in events if int(e.get("severity", 0) or 0) >= 70)

        lines = [
            str(result.get("summary", "Task complete")),
            "",
            "Scan coverage:",
            f"- Checked items shown: {checked_count}",
            f"- Findings shown: {finding_count}",
            f"- High-risk findings: {high_count}",
            "",
            "Result:",
        ]

        if finding_count:
            lines.append("- Review the findings at the top of the table.")
        else:
            lines.append("- No risky system finding was detected.")
            lines.append("- Normal checked processes/items are still displayed in the table.")

        self.system_summary_card.set_plain("\n".join(lines))


    def refresh_all(self):
        self.refresh_dashboard()
        self.refresh_system_events()
        self.refresh_quarantine()
        self.refresh_rules()

    def refresh_dashboard(self):
        stats = dashboard_stats()

        self.cards["all"].set_value(stats["total"])
        self.cards["clean"].set_value(stats["clean"])
        self.cards["review"].set_value(stats["review"])
        self.cards["malicious"].set_value(stats["malicious"])
        self.cards["quarantined"].set_value(stats["quarantined"])

        self.donut.set_values(
            clean=stats["clean"],
            review=stats["review"],
            malicious=stats["malicious"],
            errors=stats["errors"],
        )

        self.protection_widget.update_status(
            malicious=stats["malicious"],
            review=stats["review"],
            total=stats["total"],
        )

        model = malvisor_status()
        gemini = gemini_status()

        model_txt = "Protection checks are ready" if model.get("model_exists") else "Some advanced checks are not configured"
        gemini_txt = (
            "Detailed explanations ready"
            if gemini.get("google_genai_installed") and gemini.get("api_key_configured")
            else "Basic explanations enabled"
        )

        self.model_status_label.setText(
            f"{model_txt}. {gemini_txt}. Tip: high-risk files should be quarantined before opening."
        )

        self.dashboard_summary.setText(
            "Click a card or chart segment to filter the scan history. "
            "Click the same category again to clear the filter."
        )

        scans = list_scans(300)
        if self.dashboard_filter == "clean":
            scans = [s for s in scans if s.get("verdict") == "Clean"]
        elif self.dashboard_filter == "review":
            scans = [s for s in scans if s.get("verdict") == "Review needed"]
        elif self.dashboard_filter == "malicious":
            scans = [s for s in scans if s.get("verdict") in {"Malicious", "High risk"}]
        elif self.dashboard_filter == "quarantined":
            scans = [s for s in scans if int(s.get("quarantined") or 0) == 1]

        self.history_table.setRowCount(len(scans))
        for row, scan in enumerate(scans):
            bg, fg = self.verdict_colors(scan.get("verdict", ""))
            values = [
                scan.get("scanned_at"),
                scan.get("verdict"),
                scan.get("trust_label"),
                scan.get("model_type"),
                "Yes" if scan.get("quarantined") else "No",
                Path(scan.get("path", "")).name,
                scan.get("path"),
            ]
            for col, value in enumerate(values):
                self.history_table.setItem(row, col, self.item(
                    value, bold=col in {1, 2}, center=col in {1, 4},
                    fg=fg if col in {1, 2, 4} else QColor(GRAY_700),
                    bg=bg,
                ))

    def refresh_system_events(self):
        events = list_system_events(300)

        rows = []
        for event in events:
            rows.append(self._event_to_system_row(event))

        self._populate_system_table_from_rows(rows)

    def refresh_quarantine(self):
        items = list_quarantine_items()
        self.quarantine_table.setRowCount(len(items))
        for row, item in enumerate(items):
            row_bg = self.neutral_row_bg(row)
            values = [
                item.get("name"), item.get("original_path"),
                item.get("sha256"), item.get("size"), item.get("quarantine_path"),
            ]
            for col, value in enumerate(values):
                self.quarantine_table.setItem(
                    row,
                    col,
                    self.item(
                        value,
                        bold=col in {0, 2},
                        center=col == 3,
                        fg=QColor(RED_DARK if col in {0, 2} else GRAY_700),
                        bg=row_bg,
                    ),
                )

    def refresh_rules(self):
        rules = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
        self.rules_table.setRowCount(len(rules))
        for row, path in enumerate(rules):
            row_bg = self.neutral_row_bg(row)
            values = [path.name, path.stat().st_size if path.exists() else 0, str(path)]
            for col, value in enumerate(values):
                self.rules_table.setItem(
                    row,
                    col,
                    self.item(
                        value,
                        bold=col == 0,
                        center=col == 1,
                        fg=QColor(RED_DARK if col == 0 else GRAY_700),
                        bg=row_bg,
                    ),
                )

        status_lines = [
            f"Rules folder: {RULES_DIR}",
            f"Rule checker ready: {'Yes' if yara else 'No'}",
            f"Rule files found: {len(rules)}",
            "",
            "Select a rule from the table and click Validate Selected to check it.",
        ]
        self.rules_summary_card.set_plain("\n".join(status_lines))

    def validate_selected_rule(self):
        rows = self.rules_table.selectionModel().selectedRows() if self.rules_table.selectionModel() else []
        if not rows:
            QMessageBox.information(self, "No rule selected", "Select a YARA rule first.")
            return
        path = self.rules_table.item(rows[0].row(), 2).text()
        if yara is None:
            self.rules_summary_card.set_plain(
                "YARA Not Installed:\n\n"
                "- Run: python -m pip install yara-python\n"
                "- Then restart WHealth."
            )
            return
        try:
            yara.compile(filepath=path)
            self.rules_summary_card.set_plain(f"Validation Result:\n\n- Rule is VALID\n- Path: {path}")
        except Exception as exc:
            self.rules_summary_card.set_plain(f"Validation Result:\n\n- Rule is INVALID\n- Error: {exc}")

    def restore_selected_quarantine(self):
        rows = self.quarantine_table.selectionModel().selectedRows() if self.quarantine_table.selectionModel() else []
        if not rows:
            return
        qpath = self.quarantine_table.item(rows[0].row(), 4).text()
        if QMessageBox.question(
            self, "Restore File", "Restore the selected file to its original location?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            QMessageBox.information(self, "Restored", restore_quarantine_item(qpath))
            self.refresh_quarantine()
        except Exception as exc:
            QMessageBox.critical(self, "Restore Failed", str(exc))

    def delete_selected_quarantine(self):
        rows = self.quarantine_table.selectionModel().selectedRows() if self.quarantine_table.selectionModel() else []
        if not rows:
            return
        qpath = self.quarantine_table.item(rows[0].row(), 4).text()
        if QMessageBox.question(
            self, "Delete File", "Permanently delete the selected quarantined file?"
        ) != QMessageBox.StandardButton.Yes:
            return
        delete_quarantine_item(qpath)
        self.refresh_quarantine()

    def open_path(self, path: str):
        if not path:
            return
        p = Path(path)
        if not p.exists():
            QMessageBox.warning(self, "Not Found", f"Path not found:\n{path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))

    def log(self, message: str):
        self.log_box.appendPlainText(f"[{time.strftime('%H:%M:%S')}]  {message}")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont(UI_FONT_QT, 10))

    # Neutral palette so our custom stylesheet has full control
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(GRAY_50))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(GRAY_900))
    palette.setColor(QPalette.ColorRole.Base, QColor(WHITE))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(GRAY_50))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(RED_PRIMARY))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(WHITE))
    app.setPalette(palette)

    window = WHealthDesktop()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()