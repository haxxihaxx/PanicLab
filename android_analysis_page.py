"""
android_analysis_page.py — PanicLab Android Analysis UI Page
=============================================================
Drop-in replacement for the stub AndroidAnalysisPage in main.py.

Import in main.py:
    from android_analysis_page import AndroidAnalysisPageFull
Then replace AndroidAnalysisPage with AndroidAnalysisPageFull in ALL_PAGES.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from PyQt6.QtCore import (
    QMimeData, QObject, QRunnable, Qt, QThread, QThreadPool,
    QTimer, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame,
    QHBoxLayout, QLabel, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from android_analyzer import (
    AndroidCrashAnalyzer, AnalysisResult, Category, Finding, Severity,
    SourceType, format_html_report, format_markdown_report,
)

# DeviceManager is optional — only needed for ADB pull
try:
    from device_manager import DeviceManager, DeviceInfo, DevicePlatform
    _DM_AVAILABLE = True
except ImportError:
    _DM_AVAILABLE = False
    DeviceManager = None   # type: ignore[assignment,misc]
    DeviceInfo    = None   # type: ignore[assignment]
    DevicePlatform = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS / STYLES
# ═══════════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    Severity.CRITICAL: "#FF5555",
    Severity.HIGH:     "#FF8C00",
    Severity.MEDIUM:   "#FFD700",
    Severity.LOW:      "#87CEEB",
}
_SEV_BG = {
    Severity.CRITICAL: "rgba(255,85,85,0.12)",
    Severity.HIGH:     "rgba(255,140,0,0.12)",
    Severity.MEDIUM:   "rgba(255,215,0,0.10)",
    Severity.LOW:      "rgba(135,206,235,0.10)",
}
_CAT_COLOR = {
    Category.UFS_EMMC: "#F38BA8",
    Category.RAM:      "#FAB387",
    Category.PMIC:     "#F9E2AF",
    Category.THERMAL:  "#A6E3A1",
    Category.CPU_GPU:  "#89DCEB",
    Category.MODEM:    "#CBA6F7",
    Category.KERNEL:   "#B4BEFE",
    Category.WATCHDOG: "#94E2D5",
    Category.UNKNOWN:  "#6C7086",
}
_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
}

_BASE_QSS = """
QWidget#AndroidPage { background: #1E1E2E; }
QFrame#DropZone {
    background: #181825;
    border: 2px dashed #313244;
    border-radius: 12px;
}
QFrame#DropZone[drag_active="true"] {
    border-color: #CBA6F7;
    background: rgba(203,166,247,0.06);
}
QFrame[role="card"] {
    background: #181825;
    border: 1px solid #313244;
    border-radius: 8px;
}
QTextEdit#RawLog {
    background: #11111B;
    color: #A6E3A1;
    border: 1px solid #313244;
    border-radius: 6px;
    font-family: "Fira Code", "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    selection-background-color: #45475A;
}
QTableWidget {
    background: #181825;
    color: #CDD6F4;
    border: 1px solid #313244;
    border-radius: 6px;
    gridline-color: #313244;
    font-size: 11px;
    outline: none;
}
QTableWidget::item { padding: 6px 10px; border: none; }
QTableWidget::item:selected { background: #313244; color: #CDD6F4; }
QHeaderView::section {
    background: #181825;
    color: #6C7086;
    border: none;
    border-bottom: 1px solid #313244;
    padding: 6px 10px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
QScrollBar:vertical { width: 8px; background: #11111B; margin: 0; }
QScrollBar::handle:vertical { background: #313244; border-radius: 4px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QSplitter::handle { background: #313244; width: 1px; }
QPushButton.action-btn {
    background: #313244; color: #CDD6F4; border: none;
    border-radius: 6px; padding: 6px 14px; font-size: 11px;
}
QPushButton.action-btn:hover { background: #45475A; }
QPushButton.action-btn:disabled { color: #45475A; }
"""

_ACTION_BTN_QSS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:none;"
    "border-radius:6px;padding:6px 14px;font-size:11px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{color:#45475A;background:#252535;}"
)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — BACKGROUND WORKER
# ═══════════════════════════════════════════════════════════════════════════

class _WorkerSignals(QObject):
    finished = pyqtSignal(object)   # AnalysisResult
    error    = pyqtSignal(str)


class _AnalysisWorker(QRunnable):
    def __init__(self, text: str, filename: str,
                 context_lines: int = 5, min_confidence: int = 40):
        super().__init__()
        self.signals        = _WorkerSignals()
        self._text          = text
        self._filename      = filename
        self._context_lines = context_lines
        self._min_confidence = min_confidence

    @pyqtSlot()
    def run(self) -> None:
        try:
            analyzer = AndroidCrashAnalyzer(
                context_lines=self._context_lines,
                min_confidence=self._min_confidence,
            )
            result = analyzer.analyze_text(self._text, self._filename)
            self.signals.finished.emit(result)
        except Exception as exc:
            log.exception("Analysis worker error")
            self.signals.error.emit(str(exc))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2b — ADB PULL WORKER
# ═══════════════════════════════════════════════════════════════════════════

class _AdbPullSignals(QObject):
    progress = pyqtSignal(str)           # status message
    finished = pyqtSignal(str, str)      # (log_text, source_label)
    error    = pyqtSignal(str)


class _AdbPullWorker(QRunnable):
    """Pull crash logs from a connected Android device on a background thread."""

    def __init__(self, manager: "DeviceManager", serial: str) -> None:
        super().__init__()
        self.signals  = _AdbPullSignals()
        self._manager = manager
        self._serial  = serial

    @pyqtSlot()
    def run(self) -> None:
        try:
            result = self._manager.pull_android_crash_logs(
                self._serial,
                progress_cb=lambda msg: self.signals.progress.emit(msg),
            )
            if result is None:
                self.signals.error.emit(
                    "No crash logs found on device.\n"
                    "Make sure USB debugging is enabled and the device is unlocked."
                )
            else:
                log_text, source = result
                self.signals.finished.emit(log_text, source)
        except Exception as exc:
            log.exception("ADB pull worker error")
            self.signals.error.emit(str(exc))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2c — ADB DEVICE PICKER  (small inline combo + button)
# ═══════════════════════════════════════════════════════════════════════════

class AdbDevicePicker(QWidget):
    """
    A compact row that shows a device combo-box and a 'Pull from Device'
    button.  Appears in the AndroidAnalysisPageFull header when a
    DeviceManager is wired in.
    """
    pull_requested = pyqtSignal(str)  # serial

    _COMBO_QSS = (
        "QComboBox{background:#252535;color:#CDD6F4;border:1px solid #45475A;"
        "border-radius:5px;padding:3px 8px;font-size:11px;min-width:160px;}"
        "QComboBox::drop-down{border:none;width:18px;}"
        "QComboBox QAbstractItemView{background:#252535;color:#CDD6F4;"
        "selection-background-color:#45475A;border:1px solid #45475A;}"
    )
    _BTN_QSS = (
        "QPushButton{background:#8BE9FD;color:#11111B;border:none;"
        "border-radius:5px;padding:4px 12px;font-size:11px;font-weight:600;}"
        "QPushButton:hover{background:#9EFAFF;}"
        "QPushButton:disabled{background:#313244;color:#45475A;}"
    )

    def __init__(self, manager: "DeviceManager",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        phone_lbl = QLabel("📱")
        phone_lbl.setStyleSheet("font-size:14px;")
        lay.addWidget(phone_lbl)

        self._combo = QComboBox()
        self._combo.setStyleSheet(self._COMBO_QSS)
        self._combo.setPlaceholderText("No Android devices")
        lay.addWidget(self._combo)

        self._btn = QPushButton("⬇  Pull from Device")
        self._btn.setStyleSheet(self._BTN_QSS)
        self._btn.setEnabled(False)
        self._btn.clicked.connect(self._on_pull)
        lay.addWidget(self._btn)

        # Connect to DeviceManager signals
        manager.device_connected.connect(self._refresh)
        manager.device_disconnected.connect(self._refresh)
        self._refresh()

    # ── helpers ──────────────────────────────────────────────────────────

    def _android_devices(self) -> list["DeviceInfo"]:
        if not _DM_AVAILABLE or DevicePlatform is None:
            return []
        return [d for d in self._manager.devices
                if d.platform == DevicePlatform.ANDROID]

    def _refresh(self, *_args) -> None:
        self._combo.clear()
        devices = self._android_devices()
        for dev in devices:
            label = f"{dev.display_name}  [{dev.serial[:12]}]"
            self._combo.addItem(label, userData=dev.serial)
        has = bool(devices)
        self._btn.setEnabled(has)
        if not has:
            self._combo.setPlaceholderText("No Android devices")

    def _on_pull(self) -> None:
        serial = self._combo.currentData()
        if serial:
            self.pull_requested.emit(serial)



# ═══════════════════════════════════════════════════════════════════════════

class FindingCard(QFrame):
    def __init__(self, finding: Finding, index: int,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("role", "card")
        self.setStyleSheet(_BASE_QSS)
        sev_color = _SEV_COLOR.get(finding.severity, "#888")
        cat_color = _CAT_COLOR.get(finding.category, "#888")
        sev_bg    = _SEV_BG.get(finding.severity, "transparent")

        self.setStyleSheet(
            f"QFrame[role='card']{{background:#181825;"
            f"border:1px solid #313244;border-radius:8px;"
            f"border-left:4px solid {sev_color};}}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(8)

        # ── Header row ──────────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(8)

        num_lbl = QLabel(f"#{index}")
        num_lbl.setStyleSheet("color:#45475A;font-size:11px;font-weight:600;min-width:24px;")

        cat_lbl = QLabel(finding.category.value)
        cat_lbl.setStyleSheet(
            f"color:{cat_color};background:rgba(0,0,0,0.3);"
            f"padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;"
        )

        title_lbl = QLabel(finding.title)
        title_lbl.setStyleSheet("color:#CDD6F4;font-size:13px;font-weight:600;")
        title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        sev_icon = _SEV_ICON.get(finding.severity, "⚪")
        sev_lbl  = QLabel(f"{sev_icon} {finding.severity.value.upper()}")
        sev_lbl.setStyleSheet(
            f"color:{sev_color};font-size:10px;font-weight:700;"
            f"background:{sev_bg};padding:2px 8px;border-radius:4px;"
        )

        conf_lbl = QLabel(f"{finding.confidence}% · {finding.confidence_label}")
        conf_lbl.setStyleSheet("color:#6C7086;font-size:10px;")

        src_lbl = QLabel(finding.source_type.value)
        src_lbl.setStyleSheet(
            "color:#45475A;font-size:9px;background:#252535;"
            "padding:2px 6px;border-radius:3px;"
        )

        header.addWidget(num_lbl)
        header.addWidget(cat_lbl)
        header.addWidget(title_lbl)
        header.addWidget(sev_lbl)
        header.addWidget(conf_lbl)
        header.addWidget(src_lbl)
        root.addLayout(header)

        # ── Evidence ────────────────────────────────────────────────────
        if finding.evidence:
            ev_label = QLabel("Evidence")
            ev_label.setStyleSheet("color:#6C7086;font-size:10px;font-weight:600;")
            root.addWidget(ev_label)

            ev_text = QTextEdit()
            ev_text.setReadOnly(True)
            ev_text.setObjectName("RawLog")
            ev_text.setPlainText("\n".join(finding.evidence[:2]))
            ev_text.setFixedHeight(100)
            ev_text.setStyleSheet(
                "QTextEdit{background:#11111B;color:#A6E3A1;"
                "border:1px solid #252535;border-radius:6px;"
                "font-family:'Fira Code','Cascadia Code','Consolas',monospace;"
                "font-size:11px;padding:4px;}"
            )
            root.addWidget(ev_text)

        # ── Suggestions ─────────────────────────────────────────────────
        if finding.suggestions:
            sug_label = QLabel("Repair Suggestions")
            sug_label.setStyleSheet("color:#6C7086;font-size:10px;font-weight:600;margin-top:4px;")
            root.addWidget(sug_label)

            for i, sug in enumerate(finding.suggestions, 1):
                row = QHBoxLayout()
                row.setSpacing(8)
                row.setContentsMargins(0, 0, 0, 0)
                bullet = QLabel(f"{i}.")
                bullet.setStyleSheet(f"color:{sev_color};font-size:11px;font-weight:700;min-width:18px;")
                bullet.setAlignment(Qt.AlignmentFlag.AlignTop)
                text = QLabel(sug)
                text.setWordWrap(True)
                text.setStyleSheet("color:#CDD6F4;font-size:11px;")
                row.addWidget(bullet)
                row.addWidget(text, stretch=1)
                root.addLayout(row)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — DROP ZONE
# ═══════════════════════════════════════════════════════════════════════════

class DropZone(QFrame):
    file_dropped = pyqtSignal(Path)

    _ACCEPTED = {".txt", ".log", ".gz", ".zip", ""}  # empty = no ext (tombstone)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(200)
        self.setStyleSheet(_BASE_QSS)

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(12)

        icon = QLabel("🤖")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size:48px;background:transparent;border:none;")

        self._msg = QLabel(
            "Drop Android kernel logs here  —  or use ⬇  Pull from Device above\n"
            "tombstone · dumpstate · ramoops · pstore · last_kmsg\n"
            "(.txt  .log  .gz  .zip  or no extension)"
        )
        self._msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._msg.setStyleSheet("color:#45475A;font-size:12px;background:transparent;border:none;")

        lay.addWidget(icon)
        lay.addWidget(self._msg)

    def _set_drag(self, active: bool) -> None:
        self.setProperty("drag_active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        self._msg.setText(
            "Release to analyse" if active else
            "Drop Android kernel logs here\n"
            "tombstone · dumpstate · ramoops · pstore · last_kmsg\n"
            "(.txt  .log  .gz  .zip  or no extension)"
        )

    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._set_drag(True)

    def dragLeaveEvent(self, e) -> None:
        self._set_drag(False)
        super().dragLeaveEvent(e)

    def dropEvent(self, e: QDropEvent) -> None:
        self._set_drag(False)
        for url in e.mimeData().urls():
            if url.isLocalFile():
                p = Path(url.toLocalFile())
                if p.is_file():
                    e.acceptProposedAction()
                    self.file_dropped.emit(p)
                    return
        e.ignore()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — SUMMARY BAR
# ═══════════════════════════════════════════════════════════════════════════

def _summary_chip(label: str, value: str, color: str,
                  wide: bool = False) -> QFrame:
    """
    Summary chip — label on top in muted grey, value below in accent color.
    ``wide=True`` gives text chips (File, Source) more horizontal room.
    Severity chips use a fixed narrow width so the row stays compact.
    """
    chip = QFrame()
    chip.setObjectName("SummaryChip")
    chip.setStyleSheet(
        "QFrame#SummaryChip{"
        "background:#181825;"
        "border:1px solid #313244;"
        "border-radius:7px;"
        "}"
    )
    if wide:
        chip.setMinimumWidth(130)
        chip.setMaximumWidth(220)
    else:
        chip.setFixedWidth(76)

    lay = QVBoxLayout(chip)
    lay.setContentsMargins(10, 7, 10, 7)
    lay.setSpacing(3)

    # Label — small caps, muted
    l = QLabel(label.upper())
    l.setObjectName("ChipLabel")
    l.setStyleSheet(
        "QLabel#ChipLabel{"
        "color:#585B70;"
        "font-size:9px;"
        "font-weight:600;"
        "letter-spacing:0.6px;"
        "background:transparent;"
        "border:none;}"
    )
    l.setAlignment(Qt.AlignmentFlag.AlignCenter)

    # Value — readable, not oversized
    v = QLabel(value)
    v.setObjectName("ChipValue")
    v.setStyleSheet(
        f"QLabel#ChipValue{{"
        f"color:{color};"
        f"font-size:{'13px' if wide else '16px'};"
        f"font-weight:700;"
        f"background:transparent;"
        f"border:none;}}"
    )
    v.setAlignment(Qt.AlignmentFlag.AlignCenter)
    if wide:
        v.setWordWrap(False)

    lay.addWidget(l)
    lay.addWidget(v)
    return chip


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — MAIN PAGE
# ═══════════════════════════════════════════════════════════════════════════

class AndroidAnalysisPageFull(QWidget):
    """
    Full Android analysis page — replaces AndroidAnalysisPage stub.
    Compatible with BasePage contract (page_id, _title, status_message,
    on_activated, on_deactivated).
    """
    page_id = "android_analysis"
    _title  = "Android Analysis"

    from PyQt6.QtCore import pyqtSignal as _sig
    status_message = _sig(str, int)

    def __init__(self, parent: QWidget | None = None,
                 device_manager: "DeviceManager | None" = None) -> None:
        super().__init__(parent)
        self.setObjectName("AndroidPage")
        self.setStyleSheet(_BASE_QSS)
        self._result: AnalysisResult | None = None
        self._device_manager = device_manager
        self._build_ui()
        self._adb_picker: AdbDevicePicker | None = None
        if device_manager is not None and _DM_AVAILABLE:
            self._adb_picker = AdbDevicePicker(device_manager)
            self._adb_picker.pull_requested.connect(self._pull_from_device)
            # Insert picker into header action layout (right side)
            self._header_action_layout.addWidget(self._adb_picker)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QFrame()
        header.setObjectName("PageHeader")
        header.setFixedHeight(56)
        header.setStyleSheet(
            "QFrame#PageHeader{background:#181825;border-bottom:1px solid #313244;}"
            "QLabel#PageTitle{color:#CDD6F4;font-size:18px;font-weight:600;}"
            "QLabel#PageSub{color:#6C7086;font-size:11px;}"
        )
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(20, 0, 16, 0)
        h_lay.setSpacing(8)
        txt = QVBoxLayout(); txt.setSpacing(1)
        txt.addWidget(QLabel("Android Analysis", objectName="PageTitle"))
        txt.addWidget(QLabel("Kernel crash · tombstone · ramoops · pstore · last_kmsg",
                             objectName="PageSub"))
        h_lay.addLayout(txt)
        h_lay.addStretch()

        # Store for __init__ to attach ADB picker
        self._header_action_layout = QHBoxLayout()
        self._header_action_layout.setSpacing(6)
        h_lay.addLayout(self._header_action_layout)

        self._open_btn = QPushButton("📂  Open Log")
        self._open_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._open_btn.clicked.connect(self._open_dialog)

        self._export_md_btn = QPushButton("⬇️  Markdown")
        self._export_md_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._export_md_btn.setEnabled(False)
        self._export_md_btn.clicked.connect(lambda: self._export("md"))

        self._export_html_btn = QPushButton("⬇️  HTML")
        self._export_html_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._export_html_btn.setEnabled(False)
        self._export_html_btn.clicked.connect(lambda: self._export("html"))

        self._clear_btn = QPushButton("✕  Clear")
        self._clear_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._clear_btn.setEnabled(False)
        self._clear_btn.clicked.connect(self._clear)

        for btn in (self._open_btn, self._export_md_btn,
                    self._export_html_btn, self._clear_btn):
            self._header_action_layout.addWidget(btn)

        root.addWidget(header)

        # Progress bar (hidden until analysis)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            "QProgressBar{background:#313244;border:none;}"
            "QProgressBar::chunk{background:#CBA6F7;}"
        )
        self._progress.hide()
        root.addWidget(self._progress)

        # Content stack (drop zone ↔ results)
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("QStackedWidget{background:#1E1E2E;}")
        root.addWidget(self._stack, stretch=1)

        # ── Page 0: Drop zone ──────────────────────────────────────────
        drop_page = QWidget()
        dp_lay = QVBoxLayout(drop_page)
        dp_lay.setContentsMargins(20, 20, 20, 20)

        self._drop_zone = DropZone()
        self._drop_zone.file_dropped.connect(self._load_file)
        dp_lay.addWidget(self._drop_zone)

        dp_lay.addSpacing(12)
        hint = QLabel(
            "Supports: tombstone  ·  dumpstate  ·  ramoops  ·  pstore  ·  last_kmsg\n"
            "Detects:  UFS/eMMC  ·  RAM  ·  PMIC  ·  Thermal  ·  CPU/GPU  ·  Modem\n"
            "App-level crashes (Java/ANR) are automatically ignored."
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color:#313244;font-size:11px;")
        dp_lay.addWidget(hint)
        dp_lay.addStretch()
        self._stack.addWidget(drop_page)

        # ── Page 1: Results ────────────────────────────────────────────
        results_page = QWidget()
        rp_lay = QVBoxLayout(results_page)
        rp_lay.setContentsMargins(20, 12, 20, 12)
        rp_lay.setSpacing(12)

        # Summary chips
        self._summary_row = QHBoxLayout()
        self._summary_row.setSpacing(8)
        self._chip_file     = _summary_chip("File",     "—", "#CDD6F4", wide=True)
        self._chip_source   = _summary_chip("Source",   "—", "#89DCEB", wide=True)
        self._chip_critical = _summary_chip("Critical", "0", "#FF5555")
        self._chip_high     = _summary_chip("High",     "0", "#FF8C00")
        self._chip_medium   = _summary_chip("Medium",   "0", "#FFD700")
        self._chip_low      = _summary_chip("Low",      "0", "#87CEEB")
        for c in (self._chip_file, self._chip_source):
            self._summary_row.addWidget(c)

        # Subtle vertical divider between info and severity chips
        div = QFrame()
        div.setFrameShape(QFrame.Shape.VLine)
        div.setFixedWidth(1)
        div.setStyleSheet("QFrame{background:#313244;border:none;}")
        self._summary_row.addWidget(div)

        for c in (self._chip_critical, self._chip_high,
                  self._chip_medium, self._chip_low):
            self._summary_row.addWidget(c)
        self._summary_row.addStretch()
        rp_lay.addLayout(self._summary_row)

        # Splitter: findings table | raw log
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;}")

        # Left: findings cards
        findings_container = QWidget()
        findings_container.setStyleSheet("background:#1E1E2E;")
        fc_lay = QVBoxLayout(findings_container)
        fc_lay.setContentsMargins(0, 0, 6, 0)
        fc_lay.setSpacing(0)

        fl = QLabel("Findings")
        fl.setStyleSheet("color:#CDD6F4;font-size:12px;font-weight:600;padding:0 0 8px 0;")
        fc_lay.addWidget(fl)

        self._findings_scroll = QScrollArea()
        self._findings_scroll.setWidgetResizable(True)
        self._findings_scroll.setStyleSheet(
            "QScrollArea{border:none;background:#1E1E2E;}"
        )
        self._findings_inner  = QWidget()
        self._findings_inner.setStyleSheet("background:#1E1E2E;")
        self._findings_layout = QVBoxLayout(self._findings_inner)
        self._findings_layout.setContentsMargins(0, 0, 0, 0)
        self._findings_layout.setSpacing(8)
        self._findings_layout.addStretch()
        self._findings_scroll.setWidget(self._findings_inner)
        fc_lay.addWidget(self._findings_scroll, stretch=1)
        splitter.addWidget(findings_container)

        # Right: raw log preview
        raw_container = QWidget()
        raw_container.setStyleSheet("background:#1E1E2E;")
        rc_lay = QVBoxLayout(raw_container)
        rc_lay.setContentsMargins(6, 0, 0, 0)
        rc_lay.setSpacing(0)

        rl = QLabel("Raw Log Preview (first 100 lines)")
        rl.setStyleSheet("color:#CDD6F4;font-size:12px;font-weight:600;padding:0 0 8px 0;")
        rc_lay.addWidget(rl)

        self._raw_log = QTextEdit()
        self._raw_log.setReadOnly(True)
        self._raw_log.setObjectName("RawLog")
        self._raw_log.setStyleSheet(
            "QTextEdit{background:#11111B;color:#A6E3A1;"
            "border:1px solid #313244;border-radius:6px;"
            "font-family:'Fira Code','Cascadia Code','Consolas',monospace;"
            "font-size:11px;padding:8px;}"
        )
        rc_lay.addWidget(self._raw_log, stretch=1)
        splitter.addWidget(raw_container)

        splitter.setSizes([580, 420])
        rp_lay.addWidget(splitter, stretch=1)
        self._stack.addWidget(results_page)

        # ── Page 2: Not a kernel log ──────────────────────────────────
        skip_page = QWidget()
        sp_lay = QVBoxLayout(skip_page)
        sp_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_lay.setSpacing(12)
        sp_icon = QLabel("☕")
        sp_icon.setStyleSheet("font-size:48px;")
        sp_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_msg = QLabel(
            "This looks like an app-level crash (Java/Kotlin exception or ANR).\n"
            "PanicLab's Android analyzer focuses on kernel & hardware faults.\n\n"
            "Try opening a tombstone, dumpstate, last_kmsg, ramoops, or pstore file."
        )
        sp_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_msg.setStyleSheet("color:#6C7086;font-size:13px;")
        sp_lay.addWidget(sp_icon)
        sp_lay.addWidget(sp_msg)
        self._stack.addWidget(skip_page)

        # Start on drop zone
        self._stack.setCurrentIndex(0)

    # ── ADB Pull ──────────────────────────────────────────────────────────

    def _pull_from_device(self, serial: str) -> None:
        """Pull crash logs directly from the connected Android device via ADB."""
        if self._device_manager is None:
            self.status_message.emit("Device manager not available", 4000)
            return

        # Find display name for the selected device
        device_name = serial
        if _DM_AVAILABLE:
            dev = self._device_manager.get_device(serial)
            if dev:
                device_name = dev.display_name

        self.status_message.emit(f"Pulling logs from {device_name}…", 0)
        self._progress.show()
        self._open_btn.setEnabled(False)
        if self._adb_picker:
            self._adb_picker.setEnabled(False)

        worker = _AdbPullWorker(self._device_manager, serial)
        worker.signals.progress.connect(
            lambda msg: self.status_message.emit(msg, 0)
        )
        worker.signals.finished.connect(self._on_adb_result)
        worker.signals.error.connect(self._on_adb_error)
        QThreadPool.globalInstance().start(worker)

    def _on_adb_result(self, log_text: str, source: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        if self._adb_picker:
            self._adb_picker.setEnabled(True)

        # Use the virtual filename so the analyzer & UI can identify the source
        virtual_name = source.replace("/", "_").lstrip("_") + ".txt"
        self.status_message.emit(f"Analysing pulled log from {source}…", 0)
        self._progress.show()

        worker = _AnalysisWorker(text=log_text, filename=virtual_name)
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        QThreadPool.globalInstance().start(worker)

    def _on_adb_error(self, msg: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        if self._adb_picker:
            self._adb_picker.setEnabled(True)
        self.status_message.emit(f"ADB pull failed: {msg}", 8000)
        log.error("ADB pull error: %s", msg)

    # ── File open ─────────────────────────────────────────────────────────

    def _open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Android Log",
            "",
            "Log files (*.txt *.log *.gz *.zip);;All files (*)",
        )
        if path:
            self._load_file(Path(path))

    def _load_file(self, path: Path) -> None:
        if not path.exists():
            self.status_message.emit(f"File not found: {path.name}", 4000)
            return

        # Check size
        size_mib = path.stat().st_size / (1024 * 1024)
        if size_mib > 256:
            self.status_message.emit(
                f"File too large ({size_mib:.0f} MiB > 256 MiB limit)", 5000
            )
            return

        self.status_message.emit(f"Analysing {path.name}…", 0)
        self._progress.show()
        self._open_btn.setEnabled(False)

        # Read file in a thread to avoid blocking UI
        self._pending_path = path
        QTimer.singleShot(0, lambda: self._start_analysis(path))

    def _start_analysis(self, path: Path) -> None:
        try:
            # Read synchronously (fast for most log files)
            suffix = path.suffix.lower()
            if suffix == ".zip":
                from android_analyzer import AndroidCrashAnalyzer
                a = AndroidCrashAnalyzer()
                text, fname = a._read_file(path), path.name
            elif suffix == ".gz":
                import gzip
                with gzip.open(path, "rt", errors="replace") as f:
                    text = f.read()
                fname = path.name
            else:
                text  = path.read_text(encoding="utf-8", errors="replace")
                fname = path.name
        except Exception as exc:
            self._on_error(str(exc))
            return

        worker = _AnalysisWorker(text=text, filename=fname)
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        QThreadPool.globalInstance().start(worker)

    def _on_result(self, result: AnalysisResult) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        self._result = result

        if not result.is_kernel_log:
            self._stack.setCurrentIndex(2)
            self.status_message.emit("App crash detected — skipped (not a kernel log)", 5000)
            return

        # Populate summary chips
        self._update_chip(self._chip_file, result.file_name[:18] + "…"
                          if len(result.file_name) > 18 else result.file_name)
        self._update_chip(self._chip_source, result.source_type.value)

        sev_counts = {s: 0 for s in Severity}
        for f in result.findings:
            sev_counts[f.severity] += 1

        self._update_chip(self._chip_critical, str(sev_counts[Severity.CRITICAL]))
        self._update_chip(self._chip_high,     str(sev_counts[Severity.HIGH]))
        self._update_chip(self._chip_medium,   str(sev_counts[Severity.MEDIUM]))
        self._update_chip(self._chip_low,      str(sev_counts[Severity.LOW]))

        # Populate findings
        self._clear_findings()
        for i, finding in enumerate(result.findings, 1):
            card = FindingCard(finding, i)
            self._findings_layout.insertWidget(
                self._findings_layout.count() - 1, card
            )

        # Raw log
        self._raw_log.setPlainText(result.raw_preview)

        self._stack.setCurrentIndex(1)
        self._export_md_btn.setEnabled(True)
        self._export_html_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)

        n = len(result.findings)
        self.status_message.emit(
            f"Analysis complete — {n} finding{'s' if n != 1 else ''} in {result.file_name}",
            5000,
        )
        log.info("Analysis: %d findings in %s", n, result.file_name)

    def _on_error(self, msg: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        self.status_message.emit(f"Analysis error: {msg}", 8000)
        log.error("Analysis error: %s", msg)

    def _clear_findings(self) -> None:
        """Remove all finding cards (keep the stretch at the end)."""
        while self._findings_layout.count() > 1:
            item = self._findings_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _clear(self) -> None:
        self._result = None
        self._clear_findings()
        self._raw_log.clear()
        self._export_md_btn.setEnabled(False)
        self._export_html_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        self._stack.setCurrentIndex(0)
        self.status_message.emit("Cleared", 2000)

    def _update_chip(self, chip: QFrame, value: str) -> None:
        """Update the value label inside a summary chip by object name."""
        v = chip.findChild(QLabel, "ChipValue")
        if v is not None:
            v.setText(value)

    def _export(self, fmt: str) -> None:
        if not self._result:
            return
        default = self._result.file_name.replace(".", "_") + f"_report.{fmt}"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", default,
            f"{'Markdown' if fmt == 'md' else 'HTML'} files (*.{fmt})",
        )
        if not path:
            return
        try:
            content = (format_markdown_report(self._result)
                       if fmt == "md" else format_html_report(self._result))
            Path(path).write_text(content, encoding="utf-8")
            self.status_message.emit(f"Report saved → {Path(path).name}", 4000)
        except Exception as exc:
            self.status_message.emit(f"Export failed: {exc}", 5000)

    # BasePage contract
    def on_activated(self)   -> None: pass
    def on_deactivated(self) -> None: pass
