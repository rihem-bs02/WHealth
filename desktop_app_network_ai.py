from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal, QRectF, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QFileDialog, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QPlainTextEdit, QProgressBar, QSizePolicy,
    QScrollArea, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget, QComboBox
)

from app.config import REPORTS_DIR, SCAN_TARGETS_DIR, QUARANTINE_DIR, MALVISOR_MODEL_PATH
from app.database import (
    dashboard_stats, get_scan, init_db, list_detections, list_scans, list_system_events,
    save_scan, save_system_events, clear_system_events
)
from app.scanner import collect_scan_targets, scan_file
from app.reports import generate_html_report, generate_pdf_report, generate_plain_explanation
from app.malvisor_predictor import malvisor_status
from app.network_scan import run_network_audit, network_status
from app.network_ai_cicids import run_optional_cicids_ai, cicids_ai_status
from app.gemini_reporter import generate_network_ai_report, gemini_status
from app.system_scanners import (
    run_usb_scan, scan_startup_items, scan_scheduled_tasks, scan_process_behavior,
    scan_memory_processes
)
from app.quarantine_manager import list_quarantine_items, restore_quarantine_item, delete_quarantine_item
from app.config import RULES_DIR

try:
    import yara
except Exception:
    yara = None


def format_eta(seconds: float) -> str:
    try:
        seconds = max(0, int(seconds))
    except Exception:
        seconds = 0
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


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
                self.emit_progress(percent, f"Scanning {i}/{total} files. Estimated time remaining: {format_eta(eta)}")
                result = scan_file(str(path), quarantine=self.quarantine)
                results.append(result)
            self.emit_progress(86, "Building reports")
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
            self.emit_progress(100, f"Scan complete. {len(results)} file(s) checked.")
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
                self.progress.emit(25, "Checking active network connections")
                result = run_network_audit()

                self.progress.emit(55, "Checking optional network AI model")
                try:
                    result["cicids_ai"] = run_optional_cicids_ai(result)
                except Exception as exc:
                    result["cicids_ai"] = {
                        "ran": False,
                        "status": "error",
                        "summary": f"Optional network AI could not run: {exc}",
                    }

                self.progress.emit(82, "Generating Gemini network report")
                try:
                    result["ai_report"] = generate_network_ai_report(result)
                except Exception as exc:
                    result["ai_report"] = f"Gemini network report could not be generated. Local network audit is still available. Error: {exc}"
            elif self.action == "usb":
                self.progress.emit(35, "Scanning removable drive")
                result = run_usb_scan(self.quarantine, self.manual_path)
                save_system_events(result.get("events", []))
            elif self.action == "startup":
                self.progress.emit(50, "Checking startup entries")
                result = scan_startup_items()
                save_system_events(result.get("events", []))
            elif self.action == "tasks":
                self.progress.emit(50, "Checking scheduled tasks")
                result = scan_scheduled_tasks()
                save_system_events(result.get("events", []))
            elif self.action == "process":
                self.progress.emit(50, "Checking process behavior")
                result = scan_process_behavior()
                save_system_events(result.get("events", []))
            elif self.action == "memory":
                self.progress.emit(50, "Checking memory and process risk")
                result = scan_memory_processes()
                save_system_events(result.get("events", []))
            else:
                raise ValueError(f"Unknown task: {self.action}")
            self.progress.emit(100, "Task complete")
            self.finished.emit(self.action, result)
        except Exception as exc:
            self.failed.emit(str(exc))


class ClickableCard(QFrame):
    clicked = Signal(str)

    def __init__(self, key: str, title: str, value: str = "0", color: str = "#0f6cbd"):
        super().__init__()
        self.key = key
        self.color = color
        self.setObjectName("card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardTitle")
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"font-size: 30px; font-weight: 800; color: {color};")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addStretch(1)

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
        self.labels = {"clean": "Trusted", "review": "Need review", "malicious": "High risk", "errors": "Errors"}
        self.colors = {"clean": QColor("#107c10"), "review": QColor("#ffb900"), "malicious": QColor("#d13438"), "errors": QColor("#69797e")}
        self._segments: list[tuple[str, float, float]] = []
        self.setMinimumHeight(260)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_values(self, **values):
        self.values.update({k: int(v) for k, v in values.items()})
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        total = sum(self.values.values())
        side = min(self.width(), self.height()) - 50
        rect = QRectF((self.width() - side) / 2, 22, side, side)
        pen = QPen()
        pen.setWidth(28)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self._segments = []
        if total <= 0:
            pen.setColor(QColor("#d9e2ec"))
            painter.setPen(pen)
            painter.drawArc(rect, 0, 360 * 16)
            painter.setPen(QColor("#425466"))
            painter.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No scans")
            return
        start = 90 * 16
        start_degrees = 90.0
        for key, value in self.values.items():
            if value <= 0:
                continue
            span_degrees = -360.0 * value / total
            pen.setColor(self.colors[key])
            painter.setPen(pen)
            painter.drawArc(rect, int(start), int(span_degrees * 16))
            self._segments.append((key, start_degrees, start_degrees + span_degrees))
            start += int(span_degrees * 16)
            start_degrees += span_degrees
        painter.setPen(QColor("#1f2937"))
        painter.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nfiles")

    def mousePressEvent(self, event):
        # Simple click behavior: cycle by largest non-zero slice near text area is not necessary; use a menu-like order.
        total = sum(self.values.values())
        if total <= 0:
            return
        # Click left/top approximates trusted/review, right/bottom high risk/errors.
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


class AntiShieldDesktop(QMainWindow):
    def __init__(self):
        super().__init__()
        init_db()
        self.scan_worker: ScanWorker | None = None
        self.action_worker: ActionWorker | None = None
        self.last_scan_results: list[dict[str, Any]] = []
        self.last_html_report = ""
        self.last_pdf_report = ""
        self.dashboard_filter = "all"
        self.setWindowTitle("AntiShield Pro Defender")
        self.resize(1500, 900)
        self.setMinimumSize(1100, 720)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(True)
        self.tabs.setUsesScrollButtons(True)
        self.setCentralWidget(self.tabs)
        self.dashboard_tab = QWidget(); self.scan_tab = QWidget(); self.network_tab = QWidget()
        self.system_tab = QWidget(); self.quarantine_tab = QWidget(); self.rules_tab = QWidget(); self.logs_tab = QWidget()
        for widget, name in [
            (self.dashboard_tab, "Dashboard"), (self.scan_tab, "Scan Center"), (self.network_tab, "Network"),
            (self.system_tab, "System Scans"), (self.quarantine_tab, "Quarantine"),
            (self.rules_tab, "Rules and Reports"), (self.logs_tab, "Logs"),
        ]:
            self.tabs.addTab(widget, name)
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True)
        self.apply_style()
        self.build_menu()
        self.build_dashboard_tab(); self.build_scan_tab(); self.build_network_tab(); self.build_system_tab()
        self.build_quarantine_tab(); self.build_rules_tab(); self.build_logs_tab()
        self.refresh_all()
        self.statusBar().showMessage("Ready")

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #f3f6fb; }
            QWidget { font-family: 'Segoe UI', Arial, sans-serif; color: #1f2937; font-size: 12px; }
            QTabWidget::pane { border: 0; background: #f3f6fb; }
            QTabBar::tab { padding: 11px 18px; margin: 4px 2px; border-radius: 8px; color: #52616b; background: transparent; font-weight: 600; }
            QTabBar::tab:selected { background: white; color: #0f6cbd; border: 1px solid #dbeafe; }
            QFrame#hero, QFrame#panel, QFrame#card, QGroupBox { background: white; border: 1px solid #e5eaf0; border-radius: 14px; }
            QLabel#title { font-size: 26px; font-weight: 800; color: #111827; }
            QLabel#subtitle, QLabel#hint, QLabel#cardTitle { color: #667085; }
            QLabel#sectionTitle { font-size: 16px; font-weight: 700; color: #111827; }
            QGroupBox { margin-top: 12px; padding-top: 28px; font-weight: 700; }
            QGroupBox::title { subcontrol-origin: margin; left: 16px; top: 7px; }
            QPushButton { background: #0f6cbd; color: white; border: 0; border-radius: 8px; padding: 9px 16px; font-weight: 700; }
            QPushButton:hover { background: #115ea3; }
            QPushButton:disabled { background: #d0d7de; color: #6b7280; }
            QPushButton#secondary { background: #eef4fb; color: #0f6cbd; border: 1px solid #cfe4fa; }
            QPushButton#danger { background: #b42318; }
            QLineEdit, QComboBox { background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 8px 10px; }
            QTableWidget { background: white; border: 1px solid #e5eaf0; border-radius: 10px; gridline-color: #edf2f7; selection-background-color: #dbeafe; selection-color: #111827; }
            QHeaderView::section { background: #f8fafc; color: #52616b; font-weight: 700; padding: 9px; border: 0; border-bottom: 1px solid #e5eaf0; }
            QPlainTextEdit { background: white; border: 1px solid #e5eaf0; border-radius: 10px; padding: 10px; font-family: 'Segoe UI', Arial; }
            QProgressBar { border: 1px solid #d0d7de; border-radius: 8px; height: 18px; text-align: center; background: #eef2f6; }
            QProgressBar::chunk { border-radius: 8px; background: #0f6cbd; }
        """)

    def build_menu(self):
        menu = self.menuBar()
        app_menu = menu.addMenu("App")
        refresh = QAction("Refresh", self); refresh.triggered.connect(self.refresh_all); app_menu.addAction(refresh)
        reports = QAction("Open reports folder", self); reports.triggered.connect(lambda: self.open_path(str(REPORTS_DIR))); app_menu.addAction(reports)
        exit_action = QAction("Exit", self); exit_action.triggered.connect(self.close); app_menu.addAction(exit_action)

    def page(self, tab: QWidget, layout: QVBoxLayout):
        content = QWidget(); content.setLayout(layout)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content); scroll.setFrameShape(QFrame.Shape.NoFrame)
        page_layout = QVBoxLayout(tab); page_layout.setContentsMargins(0,0,0,0); page_layout.addWidget(scroll)

    def hero(self, title: str, subtitle: str) -> QFrame:
        frame = QFrame(); frame.setObjectName("hero")
        layout = QVBoxLayout(frame); layout.setContentsMargins(24,20,24,20)
        t = QLabel(title); t.setObjectName("title")
        s = QLabel(subtitle); s.setObjectName("subtitle"); s.setWordWrap(True)
        layout.addWidget(t); layout.addWidget(s)
        return frame

    def setup_table(self, table: QTableWidget):
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True); table.setSortingEnabled(True); table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def item(self, value: Any, bold: bool = False, center: bool = False, fg: QColor | None = None, bg: QColor | None = None) -> QTableWidgetItem:
        it = QTableWidgetItem(str(value if value is not None else ""))
        it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
        if bold:
            f = it.font(); f.setBold(True); it.setFont(f)
        if center: it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if fg: it.setForeground(fg)
        if bg: it.setBackground(bg)
        return it

    def verdict_colors(self, verdict: str):
        v = (verdict or "").lower()
        if v == "clean": return QColor("#e7f6e7"), QColor("#107c10")
        if v == "review needed": return QColor("#fff8df"), QColor("#8a6100")
        if v in {"malicious", "high risk"}: return QColor("#fde7e9"), QColor("#b42318")
        return QColor("#eef2f6"), QColor("#52616b")

    # Dashboard
    def build_dashboard_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Security dashboard", "A clear overview of file scans, system findings, quarantine status, and network risk."))
        cards = QGridLayout(); cards.setSpacing(12)
        self.cards = {}
        for i, (key, title, color) in enumerate([
            ("all", "Total files", "#0f6cbd"), ("clean", "Trusted", "#107c10"), ("review", "Need review", "#8a6100"),
            ("malicious", "High risk", "#b42318"), ("quarantined", "Quarantined", "#52616b")]):
            card = ClickableCard(key, title, "0", color); card.clicked.connect(self.set_dashboard_filter)
            self.cards[key] = card; cards.addWidget(card, 0, i)
        layout.addLayout(cards)
        middle = QSplitter(Qt.Orientation.Horizontal)
        chart_panel = QFrame(); chart_panel.setObjectName("panel"); cp = QVBoxLayout(chart_panel)
        title = QLabel("Scan distribution"); title.setObjectName("sectionTitle"); cp.addWidget(title)
        self.donut = DonutChart(); self.donut.clicked.connect(self.set_dashboard_filter); cp.addWidget(self.donut)
        self.dashboard_summary = QLabel(); self.dashboard_summary.setWordWrap(True); self.dashboard_summary.setObjectName("hint"); cp.addWidget(self.dashboard_summary)
        health = QFrame(); health.setObjectName("panel"); hp = QVBoxLayout(health)
        self.health_title = QLabel("Protection status"); self.health_title.setObjectName("sectionTitle")
        self.health_text = QLabel(); self.health_text.setWordWrap(True); self.health_text.setStyleSheet("font-size: 14px; line-height: 1.5;")
        self.model_status = QLabel(); self.model_status.setWordWrap(True); self.model_status.setObjectName("hint")
        hp.addWidget(self.health_title); hp.addWidget(self.health_text); hp.addSpacing(8); hp.addWidget(self.model_status); hp.addStretch(1)
        middle.addWidget(chart_panel); middle.addWidget(health); middle.setSizes([650,650])
        layout.addWidget(middle)
        group = QGroupBox("Recent scan history")
        gl = QVBoxLayout(group)
        self.history_table = QTableWidget(); self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels(["Time", "Verdict", "Trust / Risk", "AI result", "Quarantined", "File", "Path"])
        self.setup_table(self.history_table); self.history_table.setColumnWidth(0,160); self.history_table.setColumnWidth(1,130); self.history_table.setColumnWidth(2,160); self.history_table.setColumnWidth(3,230); self.history_table.setColumnWidth(4,100); self.history_table.setColumnWidth(5,220)
        gl.addWidget(self.history_table)
        layout.addWidget(group, 1)
        self.page(self.dashboard_tab, layout)

    def set_dashboard_filter(self, key: str):
        self.dashboard_filter = "all" if self.dashboard_filter == key else key
        self.refresh_dashboard()

    # Scan Center
    def build_scan_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Scan Center", "Choose a file or folder. The scan combines YARA rules, static checks, and MalVisor LightGBM AI into one easy trust/risk result."))
        box = QGroupBox("Scan target")
        bl = QVBoxLayout(box)
        row = QHBoxLayout()
        self.scan_path = QLineEdit(str(SCAN_TARGETS_DIR)); row.addWidget(self.scan_path, 1)
        bf = QPushButton("Choose file"); bf.setObjectName("secondary"); bf.clicked.connect(self.choose_scan_file); row.addWidget(bf)
        bd = QPushButton("Choose folder"); bd.setObjectName("secondary"); bd.clicked.connect(self.choose_scan_folder); row.addWidget(bd)
        self.quarantine_check = QCheckBox("Automatically quarantine files marked as malicious or high risk")
        buttons = QHBoxLayout()
        self.scan_button = QPushButton("Start scan"); self.scan_button.clicked.connect(self.start_scan); buttons.addWidget(self.scan_button)
        self.open_html_button = QPushButton("Open HTML report"); self.open_html_button.setObjectName("secondary"); self.open_html_button.clicked.connect(lambda: self.open_path(self.last_html_report)); self.open_html_button.setEnabled(False); buttons.addWidget(self.open_html_button)
        self.open_pdf_button = QPushButton("Open PDF report"); self.open_pdf_button.setObjectName("secondary"); self.open_pdf_button.clicked.connect(lambda: self.open_path(self.last_pdf_report)); self.open_pdf_button.setEnabled(False); buttons.addWidget(self.open_pdf_button)
        self.scan_progress = QProgressBar(); self.scan_progress.setRange(0,100); self.scan_progress.hide()
        self.scan_status = QLabel(""); self.scan_status.setObjectName("hint"); self.scan_status.hide()
        bl.addLayout(row); bl.addWidget(self.quarantine_check); bl.addLayout(buttons); bl.addWidget(self.scan_status); bl.addWidget(self.scan_progress)
        layout.addWidget(box)
        split = QSplitter(Qt.Orientation.Horizontal)
        left = QFrame(); left.setObjectName("panel"); ll = QVBoxLayout(left)
        filter_row = QHBoxLayout(); filter_row.addWidget(QLabel("Filter results:")); self.scan_filter = QLineEdit(); self.scan_filter.setPlaceholderText("Type a file name, verdict, finding, or AI result..."); self.scan_filter.textChanged.connect(self.apply_scan_filter); filter_row.addWidget(self.scan_filter, 1)
        ll.addLayout(filter_row)
        self.scan_table = QTableWidget(); self.scan_table.setColumnCount(8)
        self.scan_table.setHorizontalHeaderLabels(["Verdict", "Trust / Risk", "AI result", "Confidence", "Main finding", "Quarantine", "File", "Path"])
        self.setup_table(self.scan_table); self.scan_table.setColumnWidth(0,120); self.scan_table.setColumnWidth(1,150); self.scan_table.setColumnWidth(2,230); self.scan_table.setColumnWidth(3,100); self.scan_table.setColumnWidth(4,260); self.scan_table.setColumnWidth(5,100); self.scan_table.setColumnWidth(6,220)
        self.scan_table.itemSelectionChanged.connect(self.show_selected_scan_detail)
        ll.addWidget(self.scan_table)
        right = QFrame(); right.setObjectName("panel"); rl = QVBoxLayout(right)
        detail_title = QLabel("Selected file details"); detail_title.setObjectName("sectionTitle"); rl.addWidget(detail_title)
        self.scan_detail = QPlainTextEdit(); self.scan_detail.setReadOnly(True); rl.addWidget(self.scan_detail)
        split.addWidget(left); split.addWidget(right); split.setSizes([950,430])
        layout.addWidget(split, 1)
        self.page(self.scan_tab, layout)

    # Network
    def build_network_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Network audit", "Fast rule-based network review with Gemini explanation and optional CICIDS AI when flow features are available."))
        row = QHBoxLayout(); self.network_button = QPushButton("Run network audit"); self.network_button.clicked.connect(lambda: self.start_action("network")); row.addWidget(self.network_button); row.addStretch(1)
        self.network_progress = QProgressBar(); self.network_progress.setRange(0,100); self.network_progress.hide(); row.addWidget(self.network_progress)
        layout.addLayout(row)
        split = QSplitter(Qt.Orientation.Horizontal)
        left = QFrame(); left.setObjectName("panel"); ll = QVBoxLayout(left); ll.addWidget(QLabel("Active connections"))
        self.network_table = QTableWidget(); self.network_table.setColumnCount(8); self.network_table.setHorizontalHeaderLabels(["Protocol","Status","PID","Process","Local address","Remote address","Path","Risk"]); self.setup_table(self.network_table); self.network_table.setColumnWidth(0,90); self.network_table.setColumnWidth(1,110); self.network_table.setColumnWidth(2,80); self.network_table.setColumnWidth(3,180); self.network_table.setColumnWidth(4,170); self.network_table.setColumnWidth(5,170); self.network_table.setColumnWidth(6,300); ll.addWidget(self.network_table)
        right = QFrame(); right.setObjectName("panel"); rl = QVBoxLayout(right); rl.addWidget(QLabel("Network explanation and findings")); self.network_findings = QPlainTextEdit(); self.network_findings.setReadOnly(True); rl.addWidget(self.network_findings)
        split.addWidget(left); split.addWidget(right); split.setSizes([950,420]); layout.addWidget(split,1)
        self.page(self.network_tab, layout)

    # System Scans
    def build_system_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("System scans", "Check removable drives, startup items, scheduled tasks, process behavior, and memory/process risk."))
        controls = QGroupBox("Available tasks"); cl = QGridLayout(controls)
        tasks = [
            ("USB drive scan", "usb"), ("Startup items scan", "startup"), ("Scheduled tasks scan", "tasks"),
            ("Process behavior scan", "process"), ("Memory and process risk scan", "memory"),
        ]
        for i, (title, action) in enumerate(tasks):
            b = QPushButton(title); b.clicked.connect(lambda _, a=action: self.start_action(a)); cl.addWidget(b, i//3, i%3)
        self.system_progress = QProgressBar(); self.system_progress.setRange(0,100); self.system_progress.hide(); cl.addWidget(self.system_progress, 2, 0, 1, 3)
        layout.addWidget(controls)
        split = QSplitter(Qt.Orientation.Horizontal)
        left = QFrame(); left.setObjectName("panel"); ll = QVBoxLayout(left); ll.addWidget(QLabel("System findings"))
        self.system_events_table = QTableWidget(); self.system_events_table.setColumnCount(6); self.system_events_table.setHorizontalHeaderLabels(["Time", "Source", "Category", "Severity", "Title", "Details"]); self.setup_table(self.system_events_table); self.system_events_table.setColumnWidth(0,160); self.system_events_table.setColumnWidth(1,150); self.system_events_table.setColumnWidth(2,130); self.system_events_table.setColumnWidth(3,80); self.system_events_table.setColumnWidth(4,240); ll.addWidget(self.system_events_table)
        right = QFrame(); right.setObjectName("panel"); rl = QVBoxLayout(right); rl.addWidget(QLabel("Last task output")); self.system_output = QPlainTextEdit(); self.system_output.setReadOnly(True); rl.addWidget(self.system_output)
        split.addWidget(left); split.addWidget(right); split.setSizes([850,500]); layout.addWidget(split, 1)
        self.page(self.system_tab, layout)

    def build_quarantine_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Quarantine", "Files moved here are isolated from their original location. Restore only if you trust the file."))
        row = QHBoxLayout(); refresh = QPushButton("Refresh"); refresh.clicked.connect(self.refresh_quarantine); row.addWidget(refresh); restore = QPushButton("Restore selected"); restore.setObjectName("secondary"); restore.clicked.connect(self.restore_selected_quarantine); row.addWidget(restore); delete = QPushButton("Delete selected"); delete.setObjectName("danger"); delete.clicked.connect(self.delete_selected_quarantine); row.addWidget(delete); openq = QPushButton("Open quarantine folder"); openq.setObjectName("secondary"); openq.clicked.connect(lambda: self.open_path(str(QUARANTINE_DIR))); row.addWidget(openq); row.addStretch(1); layout.addLayout(row)
        self.quarantine_table = QTableWidget(); self.quarantine_table.setColumnCount(5); self.quarantine_table.setHorizontalHeaderLabels(["File", "Original path", "SHA-256", "Size", "Quarantine path"]); self.setup_table(self.quarantine_table); self.quarantine_table.setColumnWidth(0,220); self.quarantine_table.setColumnWidth(1,360); self.quarantine_table.setColumnWidth(2,250); self.quarantine_table.setColumnWidth(3,100)
        layout.addWidget(self.quarantine_table,1); self.page(self.quarantine_tab, layout)

    def build_rules_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Rules and reports", "Manage local YARA rules and open generated scan reports."))
        row = QHBoxLayout(); refresh = QPushButton("Refresh rules"); refresh.clicked.connect(self.refresh_rules); row.addWidget(refresh); validate = QPushButton("Validate selected rule"); validate.setObjectName("secondary"); validate.clicked.connect(self.validate_selected_rule); row.addWidget(validate); reports = QPushButton("Open reports folder"); reports.setObjectName("secondary"); reports.clicked.connect(lambda: self.open_path(str(REPORTS_DIR))); row.addWidget(reports); row.addStretch(1); layout.addLayout(row)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.rules_table = QTableWidget(); self.rules_table.setColumnCount(3); self.rules_table.setHorizontalHeaderLabels(["Rule file", "Size", "Path"]); self.setup_table(self.rules_table); self.rules_table.setColumnWidth(0,220); self.rules_table.setColumnWidth(1,80)
        self.rules_output = QPlainTextEdit(); self.rules_output.setReadOnly(True)
        split.addWidget(self.rules_table); split.addWidget(self.rules_output); split.setSizes([600,600]); layout.addWidget(split,1)
        self.page(self.rules_tab, layout)

    def build_logs_tab(self):
        layout = QVBoxLayout(); layout.setContentsMargins(18,18,18,18); layout.setSpacing(14)
        layout.addWidget(self.hero("Application logs", "Recent activity messages from scans, reports, and security tasks."))
        clear = QPushButton("Clear logs"); clear.setObjectName("secondary"); clear.clicked.connect(self.log_box.clear); layout.addWidget(clear, 0, Qt.AlignmentFlag.AlignLeft); layout.addWidget(self.log_box,1)
        self.page(self.logs_tab, layout)

    # Actions
    def choose_scan_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Choose file", str(Path.home()))
        if p: self.scan_path.setText(p)

    def choose_scan_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Choose folder", str(Path.home()))
        if p: self.scan_path.setText(p)

    def start_scan(self):
        path = self.scan_path.text().strip()
        if not path:
            QMessageBox.warning(self, "Missing target", "Choose a file or folder to scan."); return
        self.scan_table.setRowCount(0); self.scan_detail.clear(); self.scan_progress.setValue(0); self.scan_progress.show(); self.scan_status.show(); self.scan_button.setEnabled(False)
        self.log(f"Scan started: {path}")
        self.scan_worker = ScanWorker(path, self.quarantine_check.isChecked())
        self.scan_worker.progress.connect(self.on_scan_progress); self.scan_worker.finished.connect(self.on_scan_finished); self.scan_worker.failed.connect(self.on_scan_failed); self.scan_worker.start()

    def on_scan_progress(self, value: int, message: str):
        self.scan_progress.setValue(value); self.scan_status.setText(message); self.statusBar().showMessage(message); self.log(message)

    def on_scan_finished(self, results: list, html_report: str, pdf_report: str, explanation: str):
        self.scan_button.setEnabled(True); self.scan_progress.hide(); self.scan_status.hide()
        self.last_scan_results = results; self.last_html_report = html_report; self.last_pdf_report = pdf_report
        self.open_html_button.setEnabled(bool(html_report)); self.open_pdf_button.setEnabled(bool(pdf_report))
        self.populate_scan_table(results); self.scan_detail.setPlainText(explanation); self.refresh_all()
        QMessageBox.information(self, "Scan complete", explanation[:1200])

    def on_scan_failed(self, error: str):
        self.scan_button.setEnabled(True); self.scan_progress.hide(); self.scan_status.hide(); self.log(f"Scan failed: {error}"); QMessageBox.critical(self, "Scan failed", error)

    def populate_scan_table(self, results: list[dict[str, Any]]):
        self.scan_table.setSortingEnabled(False); self.scan_table.setRowCount(len(results))
        for row, r in enumerate(results):
            dets = r.get("detections", []) or []
            main = dets[0].get("name", "No finding") if dets else "No finding"
            bg, fg = self.verdict_colors(r.get("verdict", ""))
            values = [
                r.get("verdict"), r.get("trust_label"), r.get("model_type") or "Not applicable",
                f"{float(r.get('model_confidence',0) or 0):.0%}", main, "Yes" if r.get("quarantined") else "No",
                Path(r.get("path", "")).name, r.get("path", ""),
            ]
            for col, val in enumerate(values):
                self.scan_table.setItem(row, col, self.item(val, bold=col in {0,1}, center=col in {0,3,5}, fg=fg if col==0 else None, bg=bg if col==0 else None))
        self.scan_table.setSortingEnabled(True)
        self.apply_scan_filter()

    def apply_scan_filter(self):
        text = self.scan_filter.text().lower().strip() if hasattr(self, "scan_filter") else ""
        for row in range(self.scan_table.rowCount()):
            row_text = " ".join(self.scan_table.item(row, col).text().lower() for col in range(self.scan_table.columnCount()) if self.scan_table.item(row, col))
            self.scan_table.setRowHidden(row, bool(text and text not in row_text))

    def show_selected_scan_detail(self):
        rows = self.scan_table.selectionModel().selectedRows() if self.scan_table.selectionModel() else []
        if not rows: return
        path_item = self.scan_table.item(rows[0].row(), 7)
        if not path_item: return
        path = path_item.text()
        result = next((r for r in self.last_scan_results if r.get("path") == path), None)
        if not result:
            return
        lines = [
            f"File: {Path(path).name}", f"Path: {path}", f"Verdict: {result.get('verdict')}",
            f"Trust / risk: {result.get('trust_label')}", f"AI engine: {result.get('model_engine') or 'Not applicable'}",
            f"AI result: {result.get('model_type') or 'Not applicable'}", f"AI confidence: {float(result.get('model_confidence',0) or 0):.0%}",
            f"SHA-256: {result.get('sha256')}", "", "Findings:"
        ]
        for d in result.get("detections", []) or []:
            lines.append(f"- {d.get('engine')}: {d.get('name')} ({d.get('severity')}/100). {d.get('details')}")
        if not result.get("detections"):
            lines.append("- No suspicious finding was detected.")
        self.scan_detail.setPlainText("\n".join(lines))

    def start_action(self, action: str):
        progress = self.network_progress if action == "network" else self.system_progress
        progress.setValue(0); progress.show()
        self.action_worker = ActionWorker(action)
        self.action_worker.progress.connect(lambda v, m, p=progress: (p.setValue(v), self.statusBar().showMessage(m), self.log(m)))
        self.action_worker.finished.connect(self.on_action_finished); self.action_worker.failed.connect(lambda e: QMessageBox.critical(self, "Task failed", e)); self.action_worker.start()

    def on_action_finished(self, action: str, result: object):
        self.network_progress.hide(); self.system_progress.hide(); self.log(f"{action} finished")
        if action == "network":
            self.show_network_result(result)
        else:
            self.show_system_result(result)
        self.refresh_all()

    def show_network_result(self, result: dict[str, Any]):
        conns = result.get("connections", []) or []
        findings = result.get("findings", []) or []
        self.network_table.setRowCount(len(conns))
        for row, c in enumerate(conns):
            severity = 0
            for f in findings:
                if c.get("path") and c.get("path") in f.get("details", ""):
                    severity = max(severity, int(f.get("severity",0)))
            vals = [c.get("protocol"), c.get("status"), c.get("pid"), c.get("process"), c.get("local"), c.get("remote"), c.get("path"), severity]
            for col, val in enumerate(vals):
                self.network_table.setItem(row, col, self.item(val, center=col in {0,1,2,7}))
        ai_report = str(result.get("ai_report", "") or "").strip()
        cicids = result.get("cicids_ai", {}) or {}

        text = []
        if ai_report:
            text.append(ai_report)
            text.append("")

        text.append("Network AI status")
        text.append("-----------------")
        if cicids.get("ran"):
            text.append(f"Optional CICIDS AI: ran successfully. {cicids.get('summary', '')}")
        else:
            text.append(f"Optional CICIDS AI: not run. {cicids.get('summary', 'Add a compatible flow model and flow features to enable it.')}")
        text.append("")

        text.append("Technical details")
        text.append("-----------------")
        text.append(f"Network audit complete. Connections found: {len(conns)}")
        text.append("")
        if findings:
            text.append("Findings to review:")
            for f in findings[:50]:
                text.append(f"- {f.get('title')} ({f.get('severity')}/100): {f.get('details')}")
        else:
            text.append("No risky network connection was detected by the local rule checks.")
        self.network_findings.setPlainText("\n".join(text))

    def show_system_result(self, result: dict[str, Any]):
        lines = [str(result.get("summary", "Task complete")), ""]
        events = result.get("events", []) or []
        if events:
            lines.append("Findings:")
            for e in events[:100]: lines.append(f"- {e.get('title')} ({e.get('severity')}/100): {e.get('details')}")
        else:
            lines.append("No risky system finding was detected.")
        self.system_output.setPlainText("\n".join(lines))
        self.refresh_system_events()

    # Refresh
    def refresh_all(self):
        self.refresh_dashboard(); self.refresh_system_events(); self.refresh_quarantine(); self.refresh_rules()

    def refresh_dashboard(self):
        stats = dashboard_stats()
        self.cards["all"].set_value(stats["total"]); self.cards["clean"].set_value(stats["clean"]); self.cards["review"].set_value(stats["review"]); self.cards["malicious"].set_value(stats["malicious"]); self.cards["quarantined"].set_value(stats["quarantined"])
        self.donut.set_values(clean=stats["clean"], review=stats["review"], malicious=stats["malicious"], errors=stats["errors"])
        if stats["malicious"]:
            self.health_text.setText(f"Action recommended. {stats['malicious']} high-risk file(s) were found in recent scans.")
        elif stats["review"]:
            self.health_text.setText(f"Review recommended. {stats['review']} file(s) need attention.")
        elif stats["total"]:
            self.health_text.setText("No high-risk files are visible in the current history.")
        else:
            self.health_text.setText("No scans have been run yet. Start with Scan Center.")
        ms = malvisor_status()
        gs = gemini_status()
        gemini_text = "Gemini: available" if (gs.get("google_genai_installed") and gs.get("api_key_configured")) else "Gemini: local fallback"
        self.model_status.setText(f"AI model: {'Available' if ms['model_exists'] else 'Model file missing'} | {gemini_text} | {ms['model_path']}")
        self.dashboard_summary.setText("Click a card or chart area to filter the recent scan table. Click the same category again to show all results.")
        scans = list_scans(300)
        if self.dashboard_filter == "clean": scans = [s for s in scans if s.get("verdict") == "Clean"]
        elif self.dashboard_filter == "review": scans = [s for s in scans if s.get("verdict") == "Review needed"]
        elif self.dashboard_filter == "malicious": scans = [s for s in scans if s.get("verdict") in {"Malicious", "High risk"}]
        elif self.dashboard_filter == "quarantined": scans = [s for s in scans if int(s.get("quarantined") or 0) == 1]
        self.history_table.setRowCount(len(scans))
        for row, s in enumerate(scans):
            bg, fg = self.verdict_colors(s.get("verdict", ""))
            values = [s.get("scanned_at"), s.get("verdict"), s.get("trust_label"), s.get("model_type"), "Yes" if s.get("quarantined") else "No", Path(s.get("path","")).name, s.get("path")]
            for col, val in enumerate(values):
                self.history_table.setItem(row, col, self.item(val, bold=col in {1,2}, center=col in {1,4}, fg=fg if col==1 else None, bg=bg if col==1 else None))

    def refresh_system_events(self):
        events = list_system_events(300)
        self.system_events_table.setRowCount(len(events))
        for row, e in enumerate(events):
            values = [e.get("created_at"), e.get("source"), e.get("category"), e.get("severity"), e.get("title"), e.get("details")]
            for col, val in enumerate(values): self.system_events_table.setItem(row, col, self.item(val, center=col==3))

    def refresh_quarantine(self):
        items = list_quarantine_items()
        self.quarantine_table.setRowCount(len(items))
        for row, q in enumerate(items):
            vals = [q.get("name"), q.get("original_path"), q.get("sha256"), q.get("size"), q.get("quarantine_path")]
            for col, val in enumerate(vals): self.quarantine_table.setItem(row, col, self.item(val, center=col==3))

    def refresh_rules(self):
        rules = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
        self.rules_table.setRowCount(len(rules))
        for row, p in enumerate(rules):
            vals = [p.name, p.stat().st_size if p.exists() else 0, str(p)]
            for col, val in enumerate(vals): self.rules_table.setItem(row, col, self.item(val, center=col==1))
        self.rules_output.setPlainText(f"Rules folder: {RULES_DIR}\nYARA available: {'yes' if yara else 'no'}\nRule files: {len(rules)}")

    def validate_selected_rule(self):
        rows = self.rules_table.selectionModel().selectedRows() if self.rules_table.selectionModel() else []
        if not rows: QMessageBox.information(self, "No rule selected", "Select a YARA rule first."); return
        path = self.rules_table.item(rows[0].row(), 2).text()
        if yara is None: self.rules_output.setPlainText("YARA is not installed. Run: python -m pip install yara-python"); return
        try:
            yara.compile(filepath=path); self.rules_output.setPlainText(f"Rule is valid:\n{path}")
        except Exception as exc:
            self.rules_output.setPlainText(f"Rule is invalid:\n{exc}")

    def restore_selected_quarantine(self):
        rows = self.quarantine_table.selectionModel().selectedRows() if self.quarantine_table.selectionModel() else []
        if not rows: return
        qpath = self.quarantine_table.item(rows[0].row(), 4).text()
        if QMessageBox.question(self, "Restore file", "Restore the selected file to its original location?") != QMessageBox.StandardButton.Yes: return
        try: QMessageBox.information(self, "Restored", restore_quarantine_item(qpath)); self.refresh_quarantine()
        except Exception as exc: QMessageBox.critical(self, "Restore failed", str(exc))

    def delete_selected_quarantine(self):
        rows = self.quarantine_table.selectionModel().selectedRows() if self.quarantine_table.selectionModel() else []
        if not rows: return
        qpath = self.quarantine_table.item(rows[0].row(), 4).text()
        if QMessageBox.question(self, "Delete file", "Permanently delete the selected quarantined file?") != QMessageBox.StandardButton.Yes: return
        delete_quarantine_item(qpath); self.refresh_quarantine()

    def open_path(self, path: str):
        if not path: return
        p = Path(path)
        if not p.exists(): QMessageBox.warning(self, "Not found", f"Path not found:\n{path}"); return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))

    def log(self, message: str):
        self.log_box.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {message}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AntiShieldDesktop()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
