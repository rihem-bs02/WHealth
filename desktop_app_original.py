import os
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QRectF, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGraphicsDropShadowEffect,
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
    QSizePolicy,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config import REPORTS_DIR, SCAN_TARGETS_DIR
from app.database import (
    clear_advanced_security_events,
    get_advanced_security_stats,
    init_db,
    list_advanced_security_events,
    list_scans,
    save_scan,
)
from app.scanner import scan_path
from app.reports import generate_html_report, generate_pdf_report
from app.ai_reporter import generate_gemini_report_explanation
from app.sorel_predictor import predict_sorel_malware_type
from app.advanced_security import (
    get_advanced_security_status,
    real_time_auto_scan_manager,
    run_process_behavior_scan,
    run_startup_persistence_scan,
    run_usb_scan,
)


# ============================================================
# Worker threads
# ============================================================

class ScanWorker(QThread):
    progress = Signal(str)
    finished = Signal(list, str, str, str)
    failed = Signal(str)

    def __init__(self, path: str, quarantine: bool = False):
        super().__init__()
        self.path = path
        self.quarantine = quarantine

    def run(self):
        try:
            self.progress.emit(f"Starting scan: {self.path}")

            results = scan_path(
                self.path,
                quarantine=self.quarantine,
            )

            self.progress.emit("Generating AI explanation and reports...")

            html_report = ""
            pdf_report = ""
            ai_explanation = ""

            try:
                html_report = generate_html_report(results) or ""
            except Exception as exc:
                self.progress.emit(f"HTML report failed: {exc}")

            try:
                pdf_report = generate_pdf_report(results) or ""
            except Exception as exc:
                self.progress.emit(f"PDF report failed: {exc}")

            try:
                ai_explanation = generate_gemini_report_explanation(results)
            except Exception as exc:
                ai_explanation = (
                    "AI explanation could not be generated.\n\n"
                    f"Reason: {exc}"
                )

            html_name = Path(html_report).name if html_report else None
            pdf_name = Path(pdf_report).name if pdf_report else None

            for result in results:
                result["report_html"] = html_name
                result["report_pdf"] = pdf_name

                # SOREL ML malware type classification
                try:
                    ml_result = predict_sorel_malware_type(
                        result.get("path", "")
                    )
                    result.update(ml_result)
                except Exception as exc:
                    result["ml_malware_type"] = "ML error"
                    result["ml_malware_score"] = 0.0
                    result["ml_confidence"] = 0.0
                    result["ml_tag_scores"] = {}
                    result["ml_error"] = str(exc)

                save_scan(result)

                self.progress.emit(
                    f"{result.get('verdict')} | "
                    f"{result.get('score')}/100 | "
                    f"ML: {result.get('ml_malware_type', 'N/A')} "
                    f"({result.get('ml_malware_score', 0.0):.0%}) | "
                    f"{result.get('path')}"
                )

            self.finished.emit(
                results,
                html_report,
                pdf_report,
                ai_explanation,
            )

        except Exception as exc:
            self.failed.emit(str(exc))


class AdvancedWorker(QThread):
    progress = Signal(str)
    finished = Signal(str, object)
    failed = Signal(str)

    def __init__(self, action: str, quarantine: bool = False, manual_path: str = ""):
        super().__init__()
        self.action = action
        self.quarantine = quarantine
        self.manual_path = manual_path

    def run(self):
        try:
            if self.action == "usb":
                self.progress.emit("Running USB scan...")
                result = run_usb_scan(
                    quarantine=self.quarantine,
                    manual_path=self.manual_path,
                )
                self.finished.emit("usb", result)

            elif self.action == "startup":
                self.progress.emit("Running startup persistence scan...")
                result = run_startup_persistence_scan()
                self.finished.emit("startup", result)

            elif self.action == "process":
                self.progress.emit("Running process behavior scan...")
                result = run_process_behavior_scan()
                self.finished.emit("process", result)

            else:
                self.failed.emit(f"Unknown advanced action: {self.action}")

        except Exception as exc:
            self.failed.emit(str(exc))


# ============================================================
# Modern visual widgets
# ============================================================

class StatCard(QFrame):
    def __init__(
        self,
        title: str,
        value: str = "0",
        icon: str = "●",
        accent: str = "#ea6a4d",
        tooltip: str = "",
    ):
        super().__init__()

        self.accent = accent
        self.setObjectName("statCard")

        if tooltip:
            self.setToolTip(tooltip)

        self.setMinimumHeight(145)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(24)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(20, 20, 20, 24))
        self.setGraphicsEffect(shadow)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(8)

        self.icon_label = QLabel(icon)
        self.icon_label.setStyleSheet(f"font-size: 28px; color: {accent};")

        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(
            f"font-size: 32px; font-weight: 900; color: {accent};"
        )

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(
            "font-size: 12px; color: #8d93a1; font-weight: 800;"
        )

        layout.addWidget(self.icon_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
        layout.addStretch(1)

        self.setLayout(layout)

    def set_value(self, value):
        self.value_label.setText(str(value))


class DonutChart(QWidget):
    def __init__(self):
        super().__init__()

        self.values = {
            "Clean": 0,
            "Suspicious": 0,
            "Malicious": 0,
            "Errors": 0,
        }

        self.colors = {
            "Clean": QColor("#2eb67d"),
            "Suspicious": QColor("#f2a65a"),
            "Malicious": QColor("#ea6a4d"),
            "Errors": QColor("#b7beca"),
        }

        self.setMinimumHeight(230)

    def set_values(self, clean: int, suspicious: int, malicious: int, errors: int):
        self.values = {
            "Clean": int(clean),
            "Suspicious": int(suspicious),
            "Malicious": int(malicious),
            "Errors": int(errors),
        }
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()

        side = min(width, height) - 46
        x = (width - side) / 2
        y = (height - side) / 2

        rect = QRectF(x, y, side, side)
        total = sum(self.values.values())

        pen = QPen()
        pen.setWidth(26)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)

        if total <= 0:
            pen.setColor(QColor("#edf0f5"))
            painter.setPen(pen)
            painter.drawArc(rect, 0, 360 * 16)

            painter.setPen(QColor("#8d93a1"))
            painter.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No scans")
            return

        start_angle = 90 * 16

        for label, value in self.values.items():
            if value <= 0:
                continue

            span_angle = int(-360 * 16 * value / total)
            pen.setColor(self.colors[label])
            painter.setPen(pen)
            painter.drawArc(rect, start_angle, span_angle)
            start_angle += span_angle

        painter.setPen(QColor("#202124"))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        painter.drawText(
            rect,
            Qt.AlignmentFlag.AlignCenter,
            f"{total}\nScans",
        )


class SeverityBarChart(QWidget):
    def __init__(self):
        super().__init__()

        self.stats = {
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        self.colors = {
            "high": QColor("#ea6a4d"),
            "medium": QColor("#f2a65a"),
            "low": QColor("#2eb67d"),
        }

        self.labels = {
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }

        self.setMinimumHeight(230)

    def set_stats(self, stats: dict):
        self.stats = {
            "high": int(stats.get("high", 0)),
            "medium": int(stats.get("medium", 0)),
            "low": int(stats.get("low", 0)),
        }
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        margin = 30
        chart_width = self.width() - 2 * margin
        chart_height = self.height() - 70

        max_value = max(self.stats.values()) if self.stats else 0

        if max_value <= 0:
            painter.setPen(QColor("#8d93a1"))
            painter.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "No advanced alerts yet",
            )
            return

        keys = ["high", "medium", "low"]
        bar_gap = 24
        bar_width = int((chart_width - bar_gap * 2) / 3)

        for index, key in enumerate(keys):
            value = self.stats[key]
            ratio = value / max_value if max_value else 0

            x = margin + index * (bar_width + bar_gap)
            bar_height = int(chart_height * ratio)
            y = margin + chart_height - bar_height

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self.colors[key])
            painter.drawRoundedRect(x, y, bar_width, bar_height, 10, 10)

            painter.setPen(QColor("#202124"))
            painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            painter.drawText(
                x,
                y - 8,
                bar_width,
                20,
                Qt.AlignmentFlag.AlignCenter,
                str(value),
            )

            painter.setPen(QColor("#8d93a1"))
            painter.setFont(QFont("Segoe UI", 11))
            painter.drawText(
                x,
                margin + chart_height + 12,
                bar_width,
                22,
                Qt.AlignmentFlag.AlignCenter,
                self.labels[key],
            )


# ============================================================
# Main desktop window
# ============================================================

class AntiShieldDesktop(QMainWindow):
    def __init__(self):
        super().__init__()

        init_db()

        self.scan_worker = None
        self.advanced_worker = None

        self.last_scan_results = []
        self.last_html_report = ""
        self.last_pdf_report = ""

        self.setWindowTitle("AntiShield Desktop Protector")
        self.resize(1360, 860)
        self.setMinimumSize(980, 660)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        self.tabs.setDocumentMode(True)

        self.dashboard_tab = QWidget()
        self.scan_tab = QWidget()
        self.protection_tab = QWidget()
        self.advanced_tab = QWidget()
        self.logs_tab = QWidget()

        self.tabs.addTab(self.dashboard_tab, "🛡️ Dashboard")
        self.tabs.addTab(self.scan_tab, "🔍 Scan")
        self.tabs.addTab(self.protection_tab, "⚡ Real-time Protection")
        self.tabs.addTab(self.advanced_tab, "🧠 Advanced Security")
        self.tabs.addTab(self.logs_tab, "📜 Logs")

        self.setCentralWidget(self.tabs)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)

        self.apply_style()
        self.build_menu()
        self.build_dashboard_tab()
        self.build_scan_tab()
        self.build_protection_tab()
        self.build_advanced_tab()
        self.build_logs_tab()

        self.statusBar().showMessage("AntiShield ready")
        self.refresh_all()

    # ========================================================
    # Global style
    # ========================================================

    def apply_style(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background: #dedede;
            }

            QWidget {
                font-family: 'Segoe UI', 'Inter', Arial, sans-serif;
                font-size: 12px;
                color: #202124;
            }

            QTabWidget#mainTabs {
                background: #f8f8f8;
            }

            QTabWidget#mainTabs::pane {
                border: none;
                background: #f8f8f8;
                border-radius: 28px;
                margin: 16px;
            }

            QTabBar::tab {
                background: transparent;
                color: #8d93a1;
                min-width: 130px;
                min-height: 42px;
                margin: 8px 6px;
                padding: 10px 16px;
                border-radius: 18px;
                font-weight: 800;
                font-size: 12px;
            }

            QTabBar::tab:selected {
                background: #ffffff;
                color: #ea6a4d;
                border: 1px solid #f0ddd8;
            }

            QTabBar::tab:hover:!selected {
                background: #f1f1f1;
                color: #202124;
            }

            QScrollArea {
                background: transparent;
                border: none;
            }

            QScrollArea > QWidget > QWidget {
                background: transparent;
            }

            QWidget#pageContent {
                background: #f8f8f8;
                border-radius: 28px;
            }

            QFrame#hero {
                background: #ffffff;
                border: 1px solid #f1f1f1;
                border-radius: 28px;
            }

            QLabel#heroEyebrow {
                color: #ea6a4d;
                font-size: 11px;
                font-weight: 900;
                letter-spacing: 1px;
                text-transform: uppercase;
            }

            QLabel#heroTitle {
                color: #111111;
                font-size: 30px;
                font-weight: 900;
            }

            QLabel#heroSubtitle {
                color: #a3a3a3;
                font-size: 14px;
                font-weight: 600;
            }

            QLabel#heroBadge {
                background: #faf2ef;
                border: 1px solid #f5d7cf;
                border-radius: 34px;
                color: #ea6a4d;
                min-width: 68px;
                min-height: 68px;
                font-size: 18px;
                font-weight: 900;
            }

            QFrame#statCard,
            QFrame#softPanel {
                background: #ffffff;
                border: 1px solid #eeeeee;
                border-radius: 24px;
            }

            QFrame#statCard:hover,
            QFrame#softPanel:hover {
                border: 1px solid #f2cfc6;
                background: #fffdfc;
            }

            QGroupBox {
                background: #ffffff;
                border: 1px solid #eeeeee;
                border-radius: 24px;
                font-size: 14px;
                font-weight: 900;
                padding-top: 34px;
                margin-top: 12px;
                color: #111111;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 18px;
                top: 7px;
                color: #111111;
            }

            QPushButton {
                background: #ea6a4d;
                color: #ffffff;
                border: none;
                border-radius: 18px;
                padding: 11px 20px;
                font-weight: 900;
                font-size: 12px;
            }

            QPushButton:hover {
                background: #f27c62;
            }

            QPushButton:pressed {
                background: #d7573e;
                padding-top: 12px;
                padding-bottom: 10px;
            }

            QPushButton:disabled {
                background: #e7e7e7;
                color: #a7a7a7;
            }

            QPushButton#dangerButton {
                background: #111111;
            }

            QPushButton#dangerButton:hover {
                background: #303030;
            }

            QPushButton#secondaryButton {
                background: #f3f3f3;
                color: #202124;
                border: 1px solid #ededed;
            }

            QPushButton#secondaryButton:hover {
                background: #ffffff;
                border: 1px solid #f2cfc6;
                color: #ea6a4d;
            }

            QPushButton#successButton {
                background: #111111;
            }

            QPushButton#successButton:hover {
                background: #303030;
            }

            QPushButton#warningButton {
                background: #f2a65a;
            }

            QPushButton#warningButton:hover {
                background: #f6b978;
            }

            QLineEdit {
                background: #f6f6f6;
                border: 1px solid #eeeeee;
                border-radius: 18px;
                padding: 12px 14px;
                color: #202124;
                font-size: 13px;
                font-weight: 600;
            }

            QLineEdit:focus {
                background: #ffffff;
                border: 1px solid #ea6a4d;
            }

            QCheckBox {
                font-weight: 700;
                color: #5f6368;
                spacing: 9px;
            }

            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 6px;
                border: 1px solid #d8d8d8;
                background: #ffffff;
            }

            QCheckBox::indicator:checked {
                background: #ea6a4d;
                border: 1px solid #ea6a4d;
            }

            QTableWidget {
                background: #ffffff;
                border: 1px solid #eeeeee;
                border-radius: 18px;
                gridline-color: transparent;
                selection-background-color: #fae8e2;
                selection-color: #202124;
                alternate-background-color: #fbfbfb;
                outline: 0;
            }

            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f2f2f2;
            }

            QTableWidget::item:selected {
                background: #fae8e2;
                color: #202124;
            }

            QHeaderView::section {
                background: #fbfbfb;
                color: #9aa0a6;
                font-weight: 900;
                font-size: 11px;
                padding: 12px 8px;
                border: none;
                border-right: 1px solid #f1f1f1;
                border-bottom: 1px solid #eeeeee;
            }

            QPlainTextEdit {
                background: #ffffff;
                color: #303134;
                border: 1px solid #eeeeee;
                border-radius: 18px;
                padding: 14px;
                font-family: 'Cascadia Code', 'Consolas', monospace;
                font-size: 12px;
                selection-background-color: #fae8e2;
            }

            QProgressBar {
                background: #f0f0f0;
                border-radius: 8px;
                height: 16px;
                text-align: center;
                color: #202124;
                font-size: 10px;
                font-weight: 900;
            }

            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ea6a4d,
                    stop:1 #f2a65a
                );
                border-radius: 8px;
            }

            QScrollBar:vertical {
                background: transparent;
                width: 10px;
                margin: 8px 2px 8px 2px;
            }

            QScrollBar::handle:vertical {
                background: #d8d8d8;
                border-radius: 5px;
                min-height: 36px;
            }

            QScrollBar::handle:vertical:hover {
                background: #c6c6c6;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }

            QScrollBar:horizontal {
                background: transparent;
                height: 10px;
                margin: 2px 8px 2px 8px;
            }

            QScrollBar::handle:horizontal {
                background: #d8d8d8;
                border-radius: 5px;
                min-width: 36px;
            }

            QScrollBar::handle:horizontal:hover {
                background: #c6c6c6;
            }

            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal {
                width: 0px;
            }

            QStatusBar {
                background: #f8f8f8;
                color: #8d93a1;
                border-top: 1px solid #eeeeee;
                font-size: 11px;
                font-weight: 700;
            }

            QMenuBar {
                background: #f8f8f8;
                color: #5f6368;
                border-bottom: 1px solid #eeeeee;
                padding: 4px;
            }

            QMenuBar::item {
                padding: 6px 12px;
                border-radius: 10px;
            }

            QMenuBar::item:selected {
                background: #ffffff;
                color: #ea6a4d;
            }

            QMenu {
                background: #ffffff;
                color: #202124;
                border: 1px solid #eeeeee;
                border-radius: 14px;
                padding: 6px;
            }

            QMenu::item {
                padding: 8px 24px 8px 12px;
                border-radius: 8px;
            }

            QMenu::item:selected {
                background: #fae8e2;
                color: #ea6a4d;
            }

            QSplitter::handle {
                background: transparent;
            }

            QLabel#descLabel {
                color: #8d93a1;
                font-size: 12px;
                font-weight: 600;
            }

            QLabel#sectionTitle {
                color: #111111;
                font-size: 15px;
                font-weight: 900;
            }
            """
        )

    # ========================================================
    # UI helpers
    # ========================================================

    def add_soft_shadow(self, widget: QWidget, blur: int = 28, y: int = 12, alpha: int = 28):
        shadow = QGraphicsDropShadowEffect(widget)
        shadow.setBlurRadius(blur)
        shadow.setOffset(0, y)
        shadow.setColor(QColor(34, 34, 34, alpha))
        widget.setGraphicsEffect(shadow)
        return widget

    def set_page_layout(self, page: QWidget, layout: QVBoxLayout):
        content = QWidget()
        content.setObjectName("pageContent")
        content.setLayout(layout)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(content)

        page_layout = QVBoxLayout()
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)
        page_layout.addWidget(scroll)

        page.setLayout(page_layout)

    def create_hero(self, title: str, subtitle: str):
        hero = QFrame()
        hero.setObjectName("hero")
        self.add_soft_shadow(hero, blur=36, y=12, alpha=22)

        layout = QHBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        copy_layout = QVBoxLayout()
        copy_layout.setSpacing(4)

        eyebrow_label = QLabel("AntiShield command center")
        eyebrow_label.setObjectName("heroEyebrow")

        title_label = QLabel(title)
        title_label.setObjectName("heroTitle")
        title_label.setWordWrap(True)

        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("heroSubtitle")
        subtitle_label.setWordWrap(True)

        copy_layout.addWidget(eyebrow_label)
        copy_layout.addWidget(title_label)
        copy_layout.addWidget(subtitle_label)

        badge = QLabel("AI\nSEC")
        badge.setObjectName("heroBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addLayout(copy_layout, 1)
        layout.addWidget(
            badge,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )

        hero.setLayout(layout)
        return hero

    def create_soft_panel(self):
        panel = QFrame()
        panel.setObjectName("softPanel")
        self.add_soft_shadow(panel, blur=26, y=10, alpha=22)
        return panel

    def setup_table(self, table: QTableWidget):
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setShowGrid(False)
        table.setCornerButtonEnabled(False)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

    def make_item(
        self,
        value,
        background: QColor | None = None,
        foreground: QColor | None = None,
        bold: bool = False,
        center: bool = False,
    ):
        item = QTableWidgetItem(str(value or ""))

        flags = item.flags()
        item.setFlags(flags & ~Qt.ItemFlag.ItemIsEditable)

        if background:
            item.setBackground(background)

        if foreground:
            item.setForeground(foreground)

        if bold:
            font = item.font()
            font.setBold(True)
            item.setFont(font)

        if center:
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        return item

    def verdict_style(self, verdict: str):
        verdict = (verdict or "").lower()

        if verdict == "clean":
            return QColor("#e9f8f0"), QColor("#1f9d62")

        if verdict == "suspicious":
            return QColor("#fff4e4"), QColor("#c9822c")

        if verdict in ("malicious", "high-risk malware"):
            return QColor("#fae8e2"), QColor("#d7573e")

        if verdict == "error":
            return QColor("#f0f2f5"), QColor("#8d93a1")

        return QColor("#f8f8f8"), QColor("#8d93a1")

    def severity_style(self, severity: int):
        severity = int(severity or 0)

        if severity >= 70:
            return QColor("#fae8e2"), QColor("#d7573e")

        if severity >= 40:
            return QColor("#fff4e4"), QColor("#c9822c")

        if severity > 0:
            return QColor("#e9f8f0"), QColor("#1f9d62")

        return QColor("#f8f8f8"), QColor("#8d93a1")

    # ========================================================
    # Menu
    # ========================================================

    def build_menu(self):
        menu = self.menuBar()

        app_menu = menu.addMenu("App")

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_all)
        app_menu.addAction(refresh_action)

        open_reports_action = QAction("Open Reports Folder", self)
        open_reports_action.triggered.connect(self.open_reports_folder)
        app_menu.addAction(open_reports_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        app_menu.addAction(exit_action)

        tools_menu = menu.addMenu("Tools")

        process_action = QAction("Run Process Behavior Scan", self)
        process_action.triggered.connect(self.run_process_scan)
        tools_menu.addAction(process_action)

        startup_action = QAction("Run Startup Persistence Scan", self)
        startup_action.triggered.connect(self.run_startup_scan)
        tools_menu.addAction(startup_action)

        usb_action = QAction("Run USB Scan", self)
        usb_action.triggered.connect(self.run_usb_scan_clicked)
        tools_menu.addAction(usb_action)

    # ========================================================
    # Dashboard tab
    # ========================================================

    def build_dashboard_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        hero = self.create_hero(
            "🛡️ AntiShield Desktop Protector",
            "Intelligent antivirus dashboard — file scanning, real-time protection, AI-powered reports, and advanced threat analysis.",
        )

        top_row = QHBoxLayout()
        top_row.setSpacing(14)

        self.health_frame = QFrame()
        self.health_frame.setObjectName("statCard")
        self.add_soft_shadow(self.health_frame, blur=26, y=10, alpha=22)

        health_layout = QVBoxLayout()
        health_layout.setContentsMargins(20, 16, 20, 16)
        health_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.health_icon = QLabel("🛡️")
        self.health_icon.setStyleSheet("font-size: 48px;")
        self.health_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.health_status = QLabel("System Healthy")
        self.health_status.setStyleSheet(
            "font-size: 16px; font-weight: 900; color: #2eb67d;"
        )
        self.health_status.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.health_detail = QLabel("No threats detected")
        self.health_detail.setStyleSheet("font-size: 11px; color: #8d93a1;")
        self.health_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.last_scan_label = QLabel("Last scan: Never")
        self.last_scan_label.setStyleSheet("font-size: 11px; color: #b7beca;")
        self.last_scan_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        health_layout.addWidget(self.health_icon)
        health_layout.addWidget(self.health_status)
        health_layout.addWidget(self.health_detail)
        health_layout.addWidget(self.last_scan_label)

        self.health_frame.setLayout(health_layout)

        quick_frame = self.create_soft_panel()
        quick_layout = QVBoxLayout()
        quick_layout.setContentsMargins(20, 16, 20, 16)

        quick_title = QLabel("⚡ Quick Actions")
        quick_title.setObjectName("sectionTitle")

        quick_desc = QLabel("Start common tasks with one click")
        quick_desc.setObjectName("descLabel")

        self.quick_scan_btn = QPushButton("🔍  Quick Scan")
        self.quick_scan_btn.setObjectName("successButton")
        self.quick_scan_btn.setToolTip("Scan the default scan_targets folder for threats")
        self.quick_scan_btn.clicked.connect(self.start_quick_scan)

        self.quick_usb_btn = QPushButton("🔌  USB Scan")
        self.quick_usb_btn.setToolTip("Scan connected USB drives for autorun threats and malware")
        self.quick_usb_btn.clicked.connect(self.run_usb_scan_clicked)

        quick_refresh_btn = QPushButton("🔄  Refresh Dashboard")
        quick_refresh_btn.setObjectName("secondaryButton")
        quick_refresh_btn.setToolTip("Reload all statistics and scan history")
        quick_refresh_btn.clicked.connect(self.refresh_all)

        quick_layout.addWidget(quick_title)
        quick_layout.addWidget(quick_desc)
        quick_layout.addSpacing(8)
        quick_layout.addWidget(self.quick_scan_btn)
        quick_layout.addWidget(self.quick_usb_btn)
        quick_layout.addWidget(quick_refresh_btn)
        quick_layout.addStretch(1)

        quick_frame.setLayout(quick_layout)

        top_row.addWidget(self.health_frame, 1)
        top_row.addWidget(quick_frame, 1)

        self.total_card = StatCard(
            "Total Scans",
            "0",
            "📊",
            "#58a6ff",
            tooltip="Total number of files scanned in history",
        )
        self.clean_card = StatCard(
            "Clean",
            "0",
            "✅",
            "#2eb67d",
            tooltip="Files that passed all checks with no detections",
        )
        self.suspicious_card = StatCard(
            "Suspicious",
            "0",
            "⚠️",
            "#f2a65a",
            tooltip="Files with moderate-risk detections that need review",
        )
        self.malicious_card = StatCard(
            "Malicious",
            "0",
            "🚨",
            "#ea6a4d",
            tooltip="Files identified as malware or high-risk threats",
        )
        self.errors_card = StatCard(
            "Errors",
            "0",
            "ℹ️",
            "#8d93a1",
            tooltip="Files that could not be scanned due to errors",
        )

        cards = QGridLayout()
        cards.setSpacing(12)
        cards.addWidget(self.total_card, 0, 0)
        cards.addWidget(self.clean_card, 0, 1)
        cards.addWidget(self.suspicious_card, 0, 2)
        cards.addWidget(self.malicious_card, 0, 3)
        cards.addWidget(self.errors_card, 0, 4)

        chart_panel = self.create_soft_panel()
        chart_layout = QHBoxLayout()
        chart_layout.setContentsMargins(18, 18, 18, 18)

        self.scan_donut_chart = DonutChart()

        self.dashboard_summary_label = QLabel()
        self.dashboard_summary_label.setWordWrap(True)
        self.dashboard_summary_label.setStyleSheet(
            "font-size: 14px; color: #5f6368; line-height: 1.6;"
        )

        chart_layout.addWidget(self.scan_donut_chart, 1)
        chart_layout.addWidget(self.dashboard_summary_label, 2)
        chart_panel.setLayout(chart_layout)

        history_group = QGroupBox("📋 Recent Scan History")
        history_layout = QVBoxLayout()

        self.scan_history_table = QTableWidget()
        self.scan_history_table.setColumnCount(6)
        self.scan_history_table.setHorizontalHeaderLabels(
            [
                "ID",
                "Time (UTC)",
                "Verdict",
                "Score",
                "Quarantined",
                "File Path",
            ]
        )

        self.setup_table(self.scan_history_table)
        self.scan_history_table.setColumnWidth(0, 60)
        self.scan_history_table.setColumnWidth(1, 170)
        self.scan_history_table.setColumnWidth(2, 140)
        self.scan_history_table.setColumnWidth(3, 90)
        self.scan_history_table.setColumnWidth(4, 120)

        history_layout.addWidget(self.scan_history_table)
        history_group.setLayout(history_layout)

        layout.addWidget(hero)
        layout.addLayout(top_row)
        layout.addLayout(cards)
        layout.addWidget(chart_panel)
        layout.addWidget(history_group, 1)

        self.set_page_layout(self.dashboard_tab, layout)

    # ========================================================
    # Scan tab
    # ========================================================

    def build_scan_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        hero = self.create_hero(
            "🔍 Scan Center",
            "Scan files or folders for malware, suspicious scripts, PE threats, and generate AI-powered reports.",
        )

        scan_group = QGroupBox("📂 Select Scan Target")
        scan_layout = QVBoxLayout()

        scan_desc = QLabel(
            "Choose a file or folder to analyze. AntiShield checks YARA matches, suspicious imports, "
            "high entropy, script patterns, and AI-based threat indicators."
        )
        scan_desc.setObjectName("descLabel")
        scan_desc.setWordWrap(True)

        path_layout = QHBoxLayout()

        self.scan_path_input = QLineEdit()
        self.scan_path_input.setText(str(SCAN_TARGETS_DIR))
        self.scan_path_input.setPlaceholderText("Enter file or folder path...")

        browse_file_button = QPushButton("📄 Choose File")
        browse_file_button.setObjectName("secondaryButton")
        browse_file_button.clicked.connect(self.choose_scan_file)

        browse_folder_button = QPushButton("📁 Choose Folder")
        browse_folder_button.setObjectName("secondaryButton")
        browse_folder_button.clicked.connect(self.choose_scan_folder)

        path_layout.addWidget(self.scan_path_input, 1)
        path_layout.addWidget(browse_file_button)
        path_layout.addWidget(browse_folder_button)

        self.scan_quarantine_checkbox = QCheckBox(
            "🔒 Auto-quarantine malicious files with score ≥ 60"
        )
        self.scan_quarantine_checkbox.setToolTip(
            "When enabled, files with a risk score of 60 or higher are moved to quarantine."
        )

        self.scan_button = QPushButton("▶  Start Scan")
        self.scan_button.setObjectName("successButton")
        self.scan_button.clicked.connect(self.start_scan)

        self.open_pdf_button = QPushButton("📄 Open PDF Report")
        self.open_pdf_button.setObjectName("secondaryButton")
        self.open_pdf_button.clicked.connect(self.open_last_pdf_report)
        self.open_pdf_button.setEnabled(False)

        self.open_html_button = QPushButton("🌐 Open HTML Report")
        self.open_html_button.setObjectName("secondaryButton")
        self.open_html_button.clicked.connect(self.open_last_html_report)
        self.open_html_button.setEnabled(False)

        button_row = QHBoxLayout()
        button_row.addWidget(self.scan_button)
        button_row.addWidget(self.open_pdf_button)
        button_row.addWidget(self.open_html_button)

        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 0)
        self.scan_progress.hide()

        self.scan_status_label = QLabel("")
        self.scan_status_label.setStyleSheet(
            "color: #ea6a4d; font-size: 12px; font-weight: 800;"
        )
        self.scan_status_label.hide()

        scan_layout.addWidget(scan_desc)
        scan_layout.addSpacing(4)
        scan_layout.addLayout(path_layout)
        scan_layout.addWidget(self.scan_quarantine_checkbox)
        scan_layout.addWidget(self.scan_status_label)
        scan_layout.addLayout(button_row)
        scan_layout.addWidget(self.scan_progress)

        scan_group.setLayout(scan_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        results_group = QGroupBox("📊 Scan Results")
        results_layout = QVBoxLayout()

        self.scan_results_table = QTableWidget()
        self.scan_results_table.setColumnCount(10)
        self.scan_results_table.setHorizontalHeaderLabels(
            [
                "Verdict",
                "Score",
                "Main detection",
                "MITRE",
                "ML Type",
                "ML Malware Score",
                "ML Confidence",
                "Quarantine",
                "SHA-256",
                "Path",
            ]
        )

        self.setup_table(self.scan_results_table)
        self.scan_results_table.setColumnWidth(0, 120)
        self.scan_results_table.setColumnWidth(1, 70)
        self.scan_results_table.setColumnWidth(2, 180)
        self.scan_results_table.setColumnWidth(3, 160)
        self.scan_results_table.setColumnWidth(4, 150)
        self.scan_results_table.setColumnWidth(5, 120)
        self.scan_results_table.setColumnWidth(6, 110)
        self.scan_results_table.setColumnWidth(7, 100)
        self.scan_results_table.setColumnWidth(8, 220)

        results_layout.addWidget(self.scan_results_table)
        results_group.setLayout(results_layout)

        ai_group = QGroupBox("🧠 AI Security Analysis")
        ai_layout = QVBoxLayout()

        self.ai_explanation_box = QPlainTextEdit()
        self.ai_explanation_box.setReadOnly(True)
        self.ai_explanation_box.setPlaceholderText(
            "After a scan completes, an AI-generated security explanation will appear here.\n"
            "This includes threat analysis, risk assessment, and recommended actions."
        )

        ai_layout.addWidget(self.ai_explanation_box)
        ai_group.setLayout(ai_layout)

        splitter.addWidget(results_group)
        splitter.addWidget(ai_group)
        splitter.setSizes([850, 450])

        layout.addWidget(hero)
        layout.addWidget(scan_group)
        layout.addWidget(splitter, 1)

        self.set_page_layout(self.scan_tab, layout)

    # ========================================================
    # Protection tab
    # ========================================================

    def build_protection_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        hero = self.create_hero(
            "⚡ Real-time Protection",
            "Continuously monitor a folder and automatically scan new or modified files in real time.",
        )

        status_panel = self.create_soft_panel()
        status_layout = QVBoxLayout()
        status_layout.setContentsMargins(20, 20, 20, 20)

        self.protection_badge = QLabel("🔴 STOPPED")
        self.protection_badge.setStyleSheet(
            "font-size: 22px; font-weight: 900; color: #ea6a4d;"
        )

        self.protection_status_label = QLabel()
        self.protection_status_label.setWordWrap(True)
        self.protection_status_label.setStyleSheet(
            "font-size: 14px; font-weight: 700; color: #5f6368;"
        )

        info_label = QLabel(
            "💡 What does this do?\n"
            "Real-time protection watches a folder for new, modified, or moved files. "
            "Each detected file is automatically scanned using all engines. "
            "Threats can be auto-quarantined.\n\n"
            "Tip: Start with your Downloads folder or scan_targets."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #8d93a1; font-size: 12px;")

        status_layout.addWidget(self.protection_badge)
        status_layout.addSpacing(8)
        status_layout.addWidget(self.protection_status_label)
        status_layout.addSpacing(12)
        status_layout.addWidget(info_label)

        status_panel.setLayout(status_layout)

        config_group = QGroupBox("⚙️ Protection Settings")
        config_layout = QVBoxLayout()

        path_layout = QHBoxLayout()

        self.realtime_path_input = QLineEdit()
        self.realtime_path_input.setText(str(SCAN_TARGETS_DIR))
        self.realtime_path_input.setPlaceholderText("Select folder to monitor...")

        choose_button = QPushButton("📁 Choose Folder")
        choose_button.setObjectName("secondaryButton")
        choose_button.clicked.connect(self.choose_realtime_folder)

        path_layout.addWidget(self.realtime_path_input, 1)
        path_layout.addWidget(choose_button)

        self.realtime_quarantine_checkbox = QCheckBox(
            "🔒 Auto-quarantine files scored 60+"
        )

        start_button = QPushButton("▶  Start Protection")
        start_button.setObjectName("successButton")
        start_button.clicked.connect(self.start_realtime_protection)

        stop_button = QPushButton("⏹  Stop Protection")
        stop_button.setObjectName("dangerButton")
        stop_button.clicked.connect(self.stop_realtime_protection)

        buttons = QHBoxLayout()
        buttons.addWidget(start_button)
        buttons.addWidget(stop_button)

        config_layout.addWidget(QLabel("Folder to monitor:"))
        config_layout.addLayout(path_layout)
        config_layout.addWidget(self.realtime_quarantine_checkbox)
        config_layout.addSpacing(6)
        config_layout.addLayout(buttons)

        config_group.setLayout(config_layout)

        layout.addWidget(hero)
        layout.addWidget(status_panel)
        layout.addWidget(config_group)
        layout.addStretch(1)

        self.set_page_layout(self.protection_tab, layout)

    # ========================================================
    # Advanced tab
    # ========================================================

    def build_advanced_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        hero = self.create_hero(
            "🧠 Advanced Security",
            "Deep threat analysis — USB scanning, startup persistence detection, process behavior monitoring, and MITRE ATT&CK mapping.",
        )

        top_split = QSplitter(Qt.Orientation.Horizontal)

        chart_panel = self.create_soft_panel()
        chart_layout = QVBoxLayout()
        chart_layout.setContentsMargins(18, 18, 18, 18)

        self.advanced_stats_label = QLabel()
        self.advanced_stats_label.setWordWrap(True)
        self.advanced_stats_label.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #5f6368;"
        )

        self.severity_chart = SeverityBarChart()

        chart_layout.addWidget(self.advanced_stats_label)
        chart_layout.addWidget(self.severity_chart)

        chart_panel.setLayout(chart_layout)

        actions_group = QGroupBox("🔧 Security Scans")
        actions_layout = QVBoxLayout()
        actions_layout.setSpacing(10)

        usb_title = QLabel("🔌 USB Drive Scan")
        usb_title.setObjectName("sectionTitle")

        usb_desc = QLabel(
            "Scan removable USB drives for autorun.inf threats, malicious executables, "
            "suspicious scripts, and shortcut-based attacks."
        )
        usb_desc.setObjectName("descLabel")
        usb_desc.setWordWrap(True)

        self.usb_quarantine_checkbox = QCheckBox("🔒 Quarantine malicious USB files")

        usb_btn_row = QHBoxLayout()

        usb_button = QPushButton("▶  Scan USB Drives")
        usb_button.clicked.connect(self.run_usb_scan_clicked)

        self.usb_browse_button = QPushButton("📁 Browse Folder")
        self.usb_browse_button.setObjectName("secondaryButton")
        self.usb_browse_button.clicked.connect(self.run_usb_scan_manual)

        usb_btn_row.addWidget(usb_button)
        usb_btn_row.addWidget(self.usb_browse_button)

        startup_title = QLabel("🚀 Startup Persistence Scan")
        startup_title.setObjectName("sectionTitle")

        startup_desc = QLabel(
            "Check Startup folders, Registry Run/RunOnce keys, and scheduled tasks "
            "for suspicious persistence mechanisms."
        )
        startup_desc.setObjectName("descLabel")
        startup_desc.setWordWrap(True)

        startup_button = QPushButton("▶  Scan Startup Items")
        startup_button.clicked.connect(self.run_startup_scan)

        process_title = QLabel("🔍 Process Behavior Scan")
        process_title.setObjectName("sectionTitle")

        process_desc = QLabel(
            "Analyze running processes for suspicious command-line patterns, script interpreters, "
            "and abnormal parent-child chains."
        )
        process_desc.setObjectName("descLabel")
        process_desc.setWordWrap(True)

        process_button = QPushButton("▶  Scan Processes")
        process_button.clicked.connect(self.run_process_scan)

        clear_button = QPushButton("🗑  Clear All Alerts")
        clear_button.setObjectName("dangerButton")
        clear_button.clicked.connect(self.clear_advanced_alerts)

        actions_layout.addWidget(usb_title)
        actions_layout.addWidget(usb_desc)
        actions_layout.addWidget(self.usb_quarantine_checkbox)
        actions_layout.addLayout(usb_btn_row)

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setStyleSheet("color: #eeeeee;")
        actions_layout.addWidget(sep1)

        actions_layout.addWidget(startup_title)
        actions_layout.addWidget(startup_desc)
        actions_layout.addWidget(startup_button)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color: #eeeeee;")
        actions_layout.addWidget(sep2)

        actions_layout.addWidget(process_title)
        actions_layout.addWidget(process_desc)
        actions_layout.addWidget(process_button)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.Shape.HLine)
        sep3.setStyleSheet("color: #eeeeee;")
        actions_layout.addWidget(sep3)

        actions_layout.addWidget(clear_button)
        actions_layout.addStretch(1)

        actions_group.setLayout(actions_layout)

        top_split.addWidget(chart_panel)
        top_split.addWidget(actions_group)
        top_split.setSizes([700, 600])

        alerts_group = QGroupBox("📋 Recent Advanced Security Alerts")
        alerts_layout = QVBoxLayout()

        self.advanced_events_table = QTableWidget()
        self.advanced_events_table.setColumnCount(7)
        self.advanced_events_table.setHorizontalHeaderLabels(
            [
                "Time (UTC)",
                "Category",
                "Severity",
                "Title",
                "MITRE ATT&CK",
                "File Path",
                "Details",
            ]
        )

        self.setup_table(self.advanced_events_table)
        self.advanced_events_table.setColumnWidth(0, 170)
        self.advanced_events_table.setColumnWidth(1, 170)
        self.advanced_events_table.setColumnWidth(2, 90)
        self.advanced_events_table.setColumnWidth(3, 240)
        self.advanced_events_table.setColumnWidth(4, 210)
        self.advanced_events_table.setColumnWidth(5, 320)
        self.advanced_events_table.setColumnWidth(6, 600)

        alerts_layout.addWidget(self.advanced_events_table)
        alerts_group.setLayout(alerts_layout)

        layout.addWidget(hero)
        layout.addWidget(top_split)
        layout.addWidget(alerts_group, 1)

        self.set_page_layout(self.advanced_tab, layout)

    # ========================================================
    # Logs tab
    # ========================================================

    def build_logs_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        hero = self.create_hero(
            "📜 Application Logs",
            "Live activity log for scans, reports, and advanced security operations.",
        )

        log_desc = QLabel(
            "All scan operations, report generation, and security events are logged here with timestamps."
        )
        log_desc.setObjectName("descLabel")

        clear_button = QPushButton("🗑  Clear Logs")
        clear_button.setObjectName("secondaryButton")
        clear_button.clicked.connect(self.log_box.clear)

        layout.addWidget(hero)
        layout.addWidget(log_desc)
        layout.addWidget(clear_button)
        layout.addWidget(self.log_box, 1)

        self.set_page_layout(self.logs_tab, layout)

    # ========================================================
    # Utility actions
    # ========================================================

    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"[{timestamp}] {message}")
        self.statusBar().showMessage(f"💬 {message[:120]}")

    def choose_scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose file to scan",
            str(Path.home()),
        )

        if file_path:
            self.scan_path_input.setText(file_path)

    def choose_scan_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Choose folder to scan",
            str(Path.home()),
        )

        if folder:
            self.scan_path_input.setText(folder)

    def choose_realtime_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Choose folder for real-time protection",
            str(Path.home()),
        )

        if folder:
            self.realtime_path_input.setText(folder)

    def open_file_or_folder(self, path: str):
        if not path:
            QMessageBox.information(
                self,
                "Nothing to open",
                "No file is available yet.",
            )
            return

        path_obj = Path(path)

        if not path_obj.exists():
            QMessageBox.warning(
                self,
                "File not found",
                f"The file does not exist:\n{path}",
            )
            return

        if sys.platform.startswith("win"):
            os.startfile(str(path_obj))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path_obj)))

    def open_last_pdf_report(self):
        self.open_file_or_folder(self.last_pdf_report)

    def open_last_html_report(self):
        self.open_file_or_folder(self.last_html_report)

    def open_reports_folder(self):
        REPORTS_DIR.mkdir(exist_ok=True)
        self.open_file_or_folder(str(REPORTS_DIR))

    def friendly_scan_summary(self, results: list) -> str:
        total = len(results)
        clean = sum(1 for r in results if r.get("verdict") == "Clean")
        suspicious = sum(1 for r in results if r.get("verdict") == "Suspicious")
        malicious = sum(
            1
            for r in results
            if r.get("verdict") in ("Malicious", "High-risk malware")
        )
        errors = sum(1 for r in results if r.get("verdict") == "Error")
        quarantined = sum(1 for r in results if r.get("quarantined"))

        if malicious:
            status = "Threats were found. Review the results and do not run suspicious files."
        elif suspicious:
            status = "Suspicious files were found. Review them carefully before opening."
        elif errors:
            status = "Some files could not be scanned. Review the error entries."
        else:
            status = "No threats were detected in this scan."

        return (
            f"Files scanned: {total}\n"
            f"Clean: {clean}\n"
            f"Suspicious: {suspicious}\n"
            f"Malicious / high-risk: {malicious}\n"
            f"Errors: {errors}\n"
            f"Quarantined: {quarantined}\n\n"
            f"{status}"
        )

    # ========================================================
    # Refresh methods
    # ========================================================

    def refresh_all(self):
        self.refresh_dashboard()
        self.refresh_protection_status()
        self.refresh_advanced_events()

    def refresh_dashboard(self):
        scans = list_scans(100)

        total = len(scans)
        clean = sum(1 for s in scans if s["verdict"] == "Clean")
        suspicious = sum(1 for s in scans if s["verdict"] == "Suspicious")
        malicious = sum(
            1
            for s in scans
            if s["verdict"] in ("Malicious", "High-risk malware")
        )
        errors = sum(1 for s in scans if s["verdict"] == "Error")

        self.total_card.set_value(total)
        self.clean_card.set_value(clean)
        self.suspicious_card.set_value(suspicious)
        self.malicious_card.set_value(malicious)
        self.errors_card.set_value(errors)

        self.scan_donut_chart.set_values(
            clean=clean,
            suspicious=suspicious,
            malicious=malicious,
            errors=errors,
        )

        if malicious > 0:
            self.health_icon.setText("🛡️")
            self.health_status.setText("Threats Detected")
            self.health_status.setStyleSheet(
                "font-size: 16px; font-weight: 900; color: #ea6a4d;"
            )
            self.health_detail.setText(f"{malicious} malicious file(s) found")

        elif suspicious > 0:
            self.health_icon.setText("⚠️")
            self.health_status.setText("Review Needed")
            self.health_status.setStyleSheet(
                "font-size: 16px; font-weight: 900; color: #f2a65a;"
            )
            self.health_detail.setText(f"{suspicious} suspicious file(s) found")

        elif total > 0:
            self.health_icon.setText("✅")
            self.health_status.setText("System Healthy")
            self.health_status.setStyleSheet(
                "font-size: 16px; font-weight: 900; color: #2eb67d;"
            )
            self.health_detail.setText("No threats detected")

        else:
            self.health_icon.setText("🛡️")
            self.health_status.setText("Not Scanned Yet")
            self.health_status.setStyleSheet(
                "font-size: 16px; font-weight: 900; color: #8d93a1;"
            )
            self.health_detail.setText("Run a scan to check your system")

        if scans:
            self.last_scan_label.setText(f"Last scan: {scans[0]['scanned_at']}")
        else:
            self.last_scan_label.setText("Last scan: Never")

        if total == 0:
            summary = (
                "No scans have been performed yet.\n\n"
                "Start with the Scan tab, choose a file or folder, and click Start Scan. "
                "After scanning, AntiShield will generate an AI explanation and PDF report."
            )

        elif malicious:
            summary = (
                "Your recent scan history contains malicious or high-risk results.\n\n"
                "Recommended action: keep quarantine enabled, review the detailed scan results, "
                "and avoid opening unknown files."
            )

        elif suspicious:
            summary = (
                "Some suspicious files were found in recent scans.\n\n"
                "Recommended action: review the detections and check whether the files are trusted."
            )

        else:
            summary = (
                "Your recent scan history looks healthy.\n\n"
                "No malicious files are currently visible in the latest dashboard summary."
            )

        self.dashboard_summary_label.setText(summary)

        self.scan_history_table.setRowCount(len(scans))

        for row, scan in enumerate(scans):
            verdict = scan["verdict"]
            bg, fg = self.verdict_style(verdict)

            values = [
                scan["id"],
                scan["scanned_at"],
                verdict,
                scan["score"],
                "Yes" if scan["quarantined"] else "No",
                scan["path"],
            ]

            for col, value in enumerate(values):
                item = self.make_item(
                    value,
                    background=bg if col == 2 else None,
                    foreground=fg if col == 2 else None,
                    bold=col in (2, 3),
                    center=col in (0, 2, 3, 4),
                )
                self.scan_history_table.setItem(row, col, item)

    def refresh_protection_status(self):
        status = get_advanced_security_status()
        realtime = status.get("real_time_auto_scan", {})

        if realtime.get("running"):
            text = (
                "🟢 Real-time protection is running.\n\n"
                f"Protected folder: {realtime.get('path')}\n"
                f"Auto-quarantine: {'Enabled' if realtime.get('quarantine') else 'Disabled'}"
            )
        else:
            text = (
                "⚪ Real-time protection is stopped.\n\n"
                "Choose a folder and click Start Protection to monitor new or modified files."
            )

        if not status.get("watchdog_available"):
            text += (
                "\n\n⚠️ watchdog is not available. Install it with:\n"
                "python -m pip install watchdog"
            )

        self.protection_status_label.setText(text)

        if realtime.get("running"):
            self.protection_badge.setText("🟢 ACTIVE")
            self.protection_badge.setStyleSheet(
                "font-size: 22px; font-weight: 900; color: #2eb67d;"
            )
        else:
            self.protection_badge.setText("🔴 STOPPED")
            self.protection_badge.setStyleSheet(
                "font-size: 22px; font-weight: 900; color: #ea6a4d;"
            )

    def refresh_advanced_events(self):
        stats = get_advanced_security_stats()

        self.advanced_stats_label.setText(
            f"Total alerts: {stats['total']}   |   "
            f"High: {stats['high']}   |   "
            f"Medium: {stats['medium']}   |   "
            f"Low: {stats['low']}   |   "
            f"Max severity: {stats['max_severity']}"
        )

        self.severity_chart.set_stats(stats)

        events = list_advanced_security_events(100)
        self.advanced_events_table.setRowCount(len(events))

        for row, event in enumerate(events):
            mitre_text = "-"

            if event["mitre_id"]:
                mitre_text = (
                    f"{event['mitre_id']} | "
                    f"{event['mitre_technique']} | "
                    f"{event['mitre_tactic']}"
                )

            severity = int(event["severity"] or 0)
            sev_bg, sev_fg = self.severity_style(severity)

            values = [
                event["created_at"],
                event["category"],
                severity,
                event["title"],
                mitre_text,
                event["path"],
                event["details"],
            ]

            for col, value in enumerate(values):
                item = self.make_item(
                    value,
                    background=sev_bg if col == 2 else None,
                    foreground=sev_fg if col == 2 else None,
                    bold=col in (2, 3),
                    center=col == 2,
                )
                self.advanced_events_table.setItem(row, col, item)

    # ========================================================
    # Scan actions
    # ========================================================

    def start_scan(self):
        path = self.scan_path_input.text().strip()

        if not path:
            QMessageBox.warning(
                self,
                "Missing path",
                "Please choose a file or folder to scan.",
            )
            return

        self.scan_results_table.setRowCount(0)
        self.ai_explanation_box.setPlainText("")
        self.scan_progress.show()
        self.scan_status_label.setText("Initializing scan...")
        self.scan_status_label.show()
        self.open_pdf_button.setEnabled(False)
        self.open_html_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.quick_scan_btn.setEnabled(False)

        self.log(f"Scan started: {path}")

        self.scan_worker = ScanWorker(
            path=path,
            quarantine=self.scan_quarantine_checkbox.isChecked(),
        )

        self.scan_worker.progress.connect(self.on_scan_progress)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.failed.connect(self.scan_failed)
        self.scan_worker.start()

    def start_quick_scan(self):
        self.scan_path_input.setText(str(SCAN_TARGETS_DIR))
        self.tabs.setCurrentWidget(self.scan_tab)
        self.start_scan()

    def on_scan_progress(self, message: str):
        self.log(message)
        self.scan_status_label.setText(message[:90])

    def scan_finished(
        self,
        results: list,
        html_report: str,
        pdf_report: str,
        ai_explanation: str,
    ):
        self.scan_progress.hide()
        self.scan_status_label.hide()
        self.scan_button.setEnabled(True)
        self.quick_scan_btn.setEnabled(True)

        self.last_scan_results = results
        self.last_html_report = html_report
        self.last_pdf_report = pdf_report

        self.open_html_button.setEnabled(bool(html_report))
        self.open_pdf_button.setEnabled(bool(pdf_report))

        self.scan_results_table.setRowCount(len(results))

        for row, result in enumerate(results):
            detections = result.get("detections", [])
            first_detection = detections[0] if detections else {}

            mitre_items = result.get("mitre") or []
            first_mitre = mitre_items[0] if mitre_items else {}

            mitre_text = "-"

            if first_mitre.get("mitre_id"):
                mitre_text = (
                    f"{first_mitre.get('mitre_id')} | "
                    f"{first_mitre.get('mitre_technique')}"
                )

            verdict = result.get("verdict", "")
            bg, fg = self.verdict_style(verdict)

            ml_score_display = f"{float(result.get('ml_malware_score', 0.0)):.1%}"
            ml_conf_display = f"{float(result.get('ml_confidence', 0.0)):.1%}"

            values = [
                verdict,
                result.get("score"),
                first_detection.get("name", "No detections"),
                mitre_text,
                result.get("ml_malware_type", "Unknown"),
                ml_score_display,
                ml_conf_display,
                "Yes" if result.get("quarantined") else "No",
                result.get("sha256"),
                result.get("path"),
            ]

            for col, value in enumerate(values):
                item = self.make_item(
                    value,
                    background=bg if col == 0 else None,
                    foreground=fg if col == 0 else None,
                    bold=col in (0, 1, 4),
                    center=col in (0, 1, 5, 6, 7),
                )
                self.scan_results_table.setItem(row, col, item)

        final_explanation = ai_explanation.strip()

        if not final_explanation:
            final_explanation = self.friendly_scan_summary(results)

        self.ai_explanation_box.setPlainText(final_explanation)

        self.log(f"Scan finished. Files scanned: {len(results)}")

        if pdf_report:
            self.log(f"PDF report generated: {pdf_report}")

        if html_report:
            self.log(f"HTML report generated: {html_report}")

        self.refresh_all()

        QMessageBox.information(
            self,
            "Scan finished",
            (
                "Scan finished successfully.\n\n"
                f"{self.friendly_scan_summary(results)}\n\n"
                "AI explanation and reports are available in the Scan tab."
            ),
        )

    def scan_failed(self, error: str):
        self.scan_progress.hide()
        self.scan_status_label.hide()
        self.scan_button.setEnabled(True)
        self.quick_scan_btn.setEnabled(True)

        self.log(f"Scan failed: {error}")

        QMessageBox.critical(
            self,
            "Scan failed",
            (
                "The scan could not be completed.\n\n"
                f"Reason:\n{error}"
            ),
        )

    # ========================================================
    # Real-time protection actions
    # ========================================================

    def start_realtime_protection(self):
        path = self.realtime_path_input.text().strip()

        if not path:
            QMessageBox.warning(
                self,
                "Missing folder",
                "Please choose a folder to protect.",
            )
            return

        try:
            real_time_auto_scan_manager.start(
                path,
                quarantine=self.realtime_quarantine_checkbox.isChecked(),
            )

            self.log(f"Real-time protection started on: {path}")
            self.refresh_protection_status()

            QMessageBox.information(
                self,
                "Protection started",
                (
                    "Real-time protection is now active.\n\n"
                    "AntiShield will scan new or modified files in the selected folder."
                ),
            )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Real-time protection error",
                str(exc),
            )

    def stop_realtime_protection(self):
        try:
            real_time_auto_scan_manager.stop()

            self.log("Real-time protection stopped.")
            self.refresh_protection_status()

            QMessageBox.information(
                self,
                "Protection stopped",
                "Real-time protection has been stopped.",
            )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Real-time protection error",
                str(exc),
            )

    # ========================================================
    # Advanced actions
    # ========================================================

    def run_usb_scan_clicked(self):
        self.run_advanced_action(
            "usb",
            quarantine=self.usb_quarantine_checkbox.isChecked(),
        )

    def run_usb_scan_manual(self):
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select USB Drive or Folder to Scan",
        )

        if not folder_path:
            return

        self.run_advanced_action(
            "usb",
            quarantine=self.usb_quarantine_checkbox.isChecked(),
            manual_path=folder_path,
        )

    def run_startup_scan(self):
        self.run_advanced_action("startup")

    def run_process_scan(self):
        self.run_advanced_action("process")

    def run_advanced_action(
        self,
        action: str,
        quarantine: bool = False,
        manual_path: str = "",
    ):
        self.advanced_worker = AdvancedWorker(
            action=action,
            quarantine=quarantine,
            manual_path=manual_path,
        )

        self.advanced_worker.progress.connect(self.log)
        self.advanced_worker.finished.connect(self.advanced_finished)
        self.advanced_worker.failed.connect(self.advanced_failed)
        self.advanced_worker.start()

    def advanced_finished(self, action: str, result: object):
        self.log(f"{action} scan finished: {result}")
        self.refresh_all()

        if action == "usb":
            if isinstance(result, dict) and "summary" in result:
                message = result["summary"]
            else:
                message = (
                    "USB scan finished.\n\n"
                    "Check the Advanced Security table for removable-drive findings."
                )

        elif action == "startup":
            ignored = ""

            if isinstance(result, dict):
                ignored = (
                    f"\n\nChecked: {result.get('items_checked', 0)} item(s)"
                    f"\nIgnored normal items: {result.get('ignored_items', 0)}"
                    f"\nSaved alerts: {result.get('events_saved', 0)}"
                )

            message = (
                "Startup persistence scan finished.\n\n"
                "Normal Windows and trusted software startup entries are ignored."
                f"{ignored}"
            )

        elif action == "process":
            checked = ""

            if isinstance(result, dict):
                checked = (
                    f"\n\nChecked: {result.get('processes_checked', 0)} "
                    "running process(es)"
                )

            message = (
                "Process behavior scan finished.\n\n"
                "Suspicious command lines and abnormal parent-child process chains "
                "are shown in the table."
                f"{checked}"
            )

        else:
            message = "Advanced scan finished."

        QMessageBox.information(
            self,
            "Advanced scan finished",
            message,
        )

    def advanced_failed(self, error: str):
        self.log(f"Advanced scan failed: {error}")

        QMessageBox.critical(
            self,
            "Advanced scan failed",
            (
                "The advanced scan could not be completed.\n\n"
                f"Reason:\n{error}"
            ),
        )

    def clear_advanced_alerts(self):
        answer = QMessageBox.question(
            self,
            "Clear advanced alerts",
            "Do you want to delete all saved advanced security alerts?",
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        clear_advanced_security_events()
        self.refresh_advanced_events()
        self.log("Advanced security alerts cleared.")


# ============================================================
# Entry point
# ============================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = AntiShieldDesktop()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
