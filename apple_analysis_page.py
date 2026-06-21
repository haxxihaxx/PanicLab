"""
apple_analysis_page.py — PanicLab Apple Analysis UI Page
=========================================================
Drop-in replacement for the stub AppleAnalysisPage in main.py.

Import in main.py:
    from apple_analysis_page import AppleAnalysisPageFull

Then replace AppleAnalysisPage with AppleAnalysisPageFull in ALL_PAGES:
    # In _build_ui, inside the for-loop over ALL_PAGES:
    elif (cls.page_id == "apple_analysis"):
        page = AppleAnalysisPageFull(device_manager=self._device_manager)

Supports:
  - panic-full  (plain text pulled via idevicecrashreport)
  - panic-base  (binary/base64 blob from CrashReporter)
  - analytics   (.ips JSON wrapper files)
  - sysdiagnose (.tar.gz or .zip bundles containing panic files)

Detects: NAND · Battery · Face ID · Display · Charging · Audio · Baseband
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from PyQt6.QtCore import (
    QObject, QRunnable, Qt, QThreadPool, QTimer,
    pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame,
    QHBoxLayout, QLabel, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QSplitter, QTextEdit, QVBoxLayout, QWidget,
    QStackedWidget,
)

from apple_analyzer import (
    ApplePanicAnalyzer, AppleAnalysisResult, AppleCategory,
    Finding, Severity, AppleSourceType,
    format_html_report, format_markdown_report,
    pull_panic_full,
)

log = logging.getLogger(__name__)

# New enhanced pull module
try:
    from apple_panic_pull import (
        list_connected_devices, pull_panic_logs, build_combined_text,
        check_tools, install_instructions, AppleDevice, ToolStatus,
    )
    _PANIC_PULL_AVAILABLE = True
except ImportError:
    _PANIC_PULL_AVAILABLE = False
    log.warning("apple_panic_pull not found — using legacy pull only")

# DeviceManager is optional — only needed for idevicecrashreport pull
try:
    from device_manager import DeviceManager, DeviceInfo, DevicePlatform
    _DM_AVAILABLE = True
except ImportError:
    _DM_AVAILABLE = False
    DeviceManager  = None   # type: ignore[assignment,misc]
    DeviceInfo     = None   # type: ignore[assignment]
    DevicePlatform = None   # type: ignore[assignment]

# ─── Resolve tools/ directory (same location logic as device_manager.py) ──
_HERE      = Path(__file__).resolve().parent
_TOOLS_DIR = _HERE / "tools"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — THEME CONSTANTS
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
    AppleCategory.NAND:     "#F38BA8",
    AppleCategory.BATTERY:  "#FAB387",
    AppleCategory.FACE_ID:  "#CBA6F7",
    AppleCategory.DISPLAY:  "#89DCEB",
    AppleCategory.CHARGING: "#F9E2AF",
    AppleCategory.AUDIO:    "#A6E3A1",
    AppleCategory.BASEBAND: "#94E2D5",
    AppleCategory.KERNEL:   "#B4BEFE",
    AppleCategory.UNKNOWN:  "#6C7086",
}
_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
}

_BASE_QSS = """
QWidget#ApplePage { background: #1E1E2E; }
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
QScrollBar:vertical { width: 8px; background: #11111B; margin: 0; }
QScrollBar::handle:vertical { background: #313244; border-radius: 4px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QSplitter::handle { background: #313244; width: 1px; }
"""

_ACTION_BTN_QSS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:none;"
    "border-radius:6px;padding:6px 14px;font-size:11px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{color:#45475A;background:#252535;}"
)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — BACKGROUND WORKERS
# ═══════════════════════════════════════════════════════════════════════════

class _WorkerSignals(QObject):
    finished = pyqtSignal(object)   # AppleAnalysisResult
    error    = pyqtSignal(str)


class _AnalysisWorker(QRunnable):
    def __init__(self, text: str, filename: str,
                 source_hint: AppleSourceType = AppleSourceType.UNKNOWN,
                 context_lines: int = 5, min_confidence: int = 40):
        super().__init__()
        self.signals          = _WorkerSignals()
        self._text            = text
        self._filename        = filename
        self._source_hint     = source_hint
        self._context_lines   = context_lines
        self._min_confidence  = min_confidence

    @pyqtSlot()
    def run(self) -> None:
        try:
            analyzer = ApplePanicAnalyzer(
                context_lines=self._context_lines,
                min_confidence=self._min_confidence,
            )
            result = analyzer.analyze_text(self._text, self._filename, self._source_hint)
            self.signals.finished.emit(result)
        except Exception as exc:
            log.exception("Apple analysis worker error")
            self.signals.error.emit(str(exc))


class _PullSignals(QObject):
    progress = pyqtSignal(str)           # status message
    finished = pyqtSignal(str, str)      # (log_text, source_label)
    error    = pyqtSignal(str)


class _PullWorker(QRunnable):
    """
    Pull panic logs from an Apple device.
    Uses apple_panic_pull (enhanced) if available, else falls back to
    the legacy pull_panic_full() from apple_analyzer.
    """

    def __init__(self, udid: str, tools_dir: Path) -> None:
        super().__init__()
        self.signals    = _PullSignals()
        self._udid      = udid
        self._tools_dir = tools_dir

    @pyqtSlot()
    def run(self) -> None:
        try:
            if _PANIC_PULL_AVAILABLE:
                self._run_enhanced()
            else:
                self._run_legacy()
        except Exception as exc:
            log.exception("Apple pull worker error")
            self.signals.error.emit(str(exc))

    def _run_enhanced(self) -> None:
        """Use apple_panic_pull for panic-full, panic-base, analytics, sysdiagnose."""
        udid_short = self._udid[:12]
        self.signals.progress.emit(f"Connecting to device {udid_short}…")

        with tempfile.TemporaryDirectory(prefix="paniclab_") as tmp:
            dest = Path(tmp)
            result = pull_panic_logs(
                udid=self._udid,
                dest_dir=dest,
                tools_dir=self._tools_dir,
                progress_cb=lambda msg: self.signals.progress.emit(msg),
            )

            if not result.success:
                self.signals.error.emit(result.error or "Pull failed — no panic logs found.")
                return

            self.signals.progress.emit(
                f"Pulled {len(result.files)} file(s) via {result.method} — analysing…"
            )
            combined, fname = build_combined_text(result.files)
            if not combined.strip():
                self.signals.error.emit("Pulled files were empty. Is device trusted?")
                return
            self.signals.finished.emit(combined, fname)

    def _run_legacy(self) -> None:
        """Legacy fallback: idevicecrashreport via apple_analyzer.pull_panic_full."""
        udid_short = self._udid[:12]
        self.signals.progress.emit(f"Pulling panic logs from {udid_short}…")
        with tempfile.TemporaryDirectory(prefix="paniclab_") as tmp:
            dest = Path(tmp)
            pulled = pull_panic_full(self._udid, dest, self._tools_dir)
            if not pulled:
                self.signals.error.emit(
                    "No panic logs found on device.\n"
                    "Make sure the device is trusted (paired) and "
                    "idevicecrashreport is installed or bundled in tools/."
                )
                return
            self.signals.progress.emit(f"Pulled {len(pulled)} file(s) — analysing…")
            parts: list[str] = []
            for p in pulled:
                try:
                    parts.append(f"=== {p.name} ===\n{p.read_text(errors='replace')}")
                except Exception:
                    continue
            combined = "\n\n".join(parts)
            fname = pulled[0].name if len(pulled) == 1 else f"{len(pulled)} panic files"
            self.signals.finished.emit(combined, fname)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — FINDING CARD WIDGET
# ═══════════════════════════════════════════════════════════════════════════

class FindingCard(QFrame):
    """Renders a single Finding as a styled card."""

    def __init__(self, finding: Finding, index: int,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("role", "card")
        self.setStyleSheet(
            f"QFrame[role='card']{{background:{_SEV_BG.get(finding.severity,'rgba(49,50,68,0.5)')};"
            f"border:1px solid {_SEV_COLOR.get(finding.severity,'#313244')};"
            f"border-radius:8px;padding:4px;}}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(6)

        sev_color = _SEV_COLOR.get(finding.severity, "#6C7086")
        cat_color = _CAT_COLOR.get(finding.category, "#6C7086")

        # ── Header row ───────────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(6)

        num_lbl = QLabel(f"{index:02d}")
        num_lbl.setStyleSheet("color:#45475A;font-size:11px;font-weight:700;min-width:22px;")

        icon = _SEV_ICON.get(finding.severity, "⚪")
        sev_lbl = QLabel(f"{icon} {finding.severity.value.upper()}")
        sev_lbl.setStyleSheet(
            f"color:{sev_color};font-size:10px;font-weight:700;"
            f"background:{sev_color}22;padding:2px 7px;border-radius:4px;"
        )

        cat_lbl = QLabel(finding.category.value)
        cat_lbl.setStyleSheet(
            f"color:{cat_color};font-size:10px;font-weight:600;"
            f"background:{cat_color}22;padding:2px 7px;border-radius:4px;"
        )

        title_lbl = QLabel(finding.title)
        title_lbl.setStyleSheet("color:#CDD6F4;font-size:12px;font-weight:600;")
        title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        conf_lbl = QLabel(f"{finding.confidence}% · {finding.confidence_label}")
        conf_lbl.setStyleSheet(
            "color:#CDD6F4;font-size:10px;background:#252535;"
            "padding:2px 7px;border-radius:3px;"
        )

        src_lbl = QLabel(finding.source_type.value)
        src_lbl.setStyleSheet(
            "color:#45475A;font-size:9px;background:#252535;"
            "padding:2px 6px;border-radius:3px;"
        )

        header.addWidget(num_lbl)
        header.addWidget(sev_lbl)
        header.addWidget(cat_lbl)
        header.addWidget(title_lbl)
        header.addWidget(conf_lbl)
        header.addWidget(src_lbl)
        root.addLayout(header)

        # ── Evidence ─────────────────────────────────────────────────────
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

        # ── Suggestions ───────────────────────────────────────────────────
        if finding.suggestions:
            sug_label = QLabel("Repair Suggestions")
            sug_label.setStyleSheet(
                "color:#6C7086;font-size:10px;font-weight:600;margin-top:4px;"
            )
            root.addWidget(sug_label)

            for i, sug in enumerate(finding.suggestions, 1):
                row = QHBoxLayout()
                row.setSpacing(8)
                row.setContentsMargins(0, 0, 0, 0)
                bullet = QLabel(f"{i}.")
                bullet.setStyleSheet(
                    f"color:{sev_color};font-size:11px;font-weight:700;min-width:18px;"
                )
                bullet.setAlignment(Qt.AlignmentFlag.AlignTop)
                text_lbl = QLabel(sug)
                text_lbl.setWordWrap(True)
                text_lbl.setStyleSheet("color:#CDD6F4;font-size:11px;")
                row.addWidget(bullet)
                row.addWidget(text_lbl, stretch=1)
                root.addLayout(row)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — DROP ZONE
# ═══════════════════════════════════════════════════════════════════════════

class DropZone(QFrame):
    file_dropped = pyqtSignal(Path)

    _ACCEPTED = {".ips", ".panic", ".txt", ".log", ".gz", ".tgz", ".zip", ""}

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(200)
        self.setStyleSheet(_BASE_QSS)

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(12)

        icon = QLabel("🍎")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size:48px;background:transparent;border:none;")

        self._msg = QLabel(
            "Drop Apple panic logs here — or use ⬇  Pull from Device above\n"
            "panic-full · panic-base · analytics (.ips) · sysdiagnose bundle\n"
            "(.ips  .panic  .txt  .log  .gz  .tgz  .zip)"
        )
        self._msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._msg.setStyleSheet(
            "color:#45475A;font-size:12px;background:transparent;border:none;"
        )

        lay.addWidget(icon)
        lay.addWidget(self._msg)

    def _set_drag(self, active: bool) -> None:
        self.setProperty("drag_active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        self._msg.setText(
            "Release to analyse" if active else
            "Drop Apple panic logs here\n"
            "panic-full · panic-base · .ips analytics · sysdiagnose bundle\n"
            "(.ips  .panic  .txt  .log  .gz  .tgz  .zip)"
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
# SECTION 5 — SUMMARY CHIP
# ═══════════════════════════════════════════════════════════════════════════

def _summary_chip(label: str, value: str, color: str,
                  wide: bool = False) -> QFrame:
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
        chip.setMaximumWidth(240)
    else:
        chip.setFixedWidth(76)

    lay = QVBoxLayout(chip)
    lay.setContentsMargins(10, 7, 10, 7)
    lay.setSpacing(3)

    l = QLabel(label.upper())
    l.setObjectName("ChipLabel")
    l.setStyleSheet(
        "QLabel#ChipLabel{color:#585B70;font-size:9px;font-weight:600;"
        "letter-spacing:0.6px;background:transparent;border:none;}"
    )
    l.setAlignment(Qt.AlignmentFlag.AlignCenter)

    v = QLabel(value)
    v.setObjectName("ChipValue")
    v.setStyleSheet(
        f"QLabel#ChipValue{{color:{color};"
        f"font-size:{'13px' if wide else '16px'};"
        f"font-weight:700;background:transparent;border:none;}}"
    )
    v.setAlignment(Qt.AlignmentFlag.AlignCenter)
    if wide:
        v.setWordWrap(False)

    lay.addWidget(l)
    lay.addWidget(v)
    return chip


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — APPLE DEVICE PICKER
# ═══════════════════════════════════════════════════════════════════════════

class AppleDevicePicker(QWidget):
    """
    Enhanced device picker using apple_panic_pull for device discovery.

    Shows:
      - Live device list (idevice_id or DeviceManager)
      - Tool status indicators (idevicecrashreport, ideviceinfo, etc.)
      - Pull Panic Logs button
      - Refresh button
    """
    pull_requested = pyqtSignal(str)   # UDID

    _COMBO_QSS = (
        "QComboBox{background:#252535;color:#CDD6F4;border:1px solid #45475A;"
        "border-radius:5px;padding:3px 8px;font-size:11px;min-width:160px;}"
        "QComboBox::drop-down{border:none;width:18px;}"
        "QComboBox QAbstractItemView{background:#252535;color:#CDD6F4;"
        "selection-background-color:#45475A;border:1px solid #45475A;}"
    )
    _BTN_QSS = (
        "QPushButton{background:#CBA6F7;color:#11111B;border:none;"
        "border-radius:5px;padding:4px 12px;font-size:11px;font-weight:600;}"
        "QPushButton:hover{background:#D9C0FF;}"
        "QPushButton:disabled{background:#313244;color:#45475A;}"
    )
    _REFRESH_QSS = (
        "QPushButton{background:#313244;color:#CDD6F4;border:none;"
        "border-radius:5px;padding:4px 8px;font-size:11px;}"
        "QPushButton:hover{background:#45475A;}"
    )

    def __init__(self, manager: "DeviceManager | None" = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._known_devices: list = []   # AppleDevice or DeviceInfo

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        phone_lbl = QLabel("📱")
        phone_lbl.setStyleSheet("font-size:14px;")
        lay.addWidget(phone_lbl)

        self._combo = QComboBox()
        self._combo.setStyleSheet(self._COMBO_QSS)
        self._combo.setPlaceholderText("No Apple devices")
        lay.addWidget(self._combo)

        self._refresh_btn = QPushButton("↺")
        self._refresh_btn.setToolTip("Refresh device list")
        self._refresh_btn.setStyleSheet(self._REFRESH_QSS)
        self._refresh_btn.setFixedWidth(28)
        self._refresh_btn.clicked.connect(self._refresh)
        lay.addWidget(self._refresh_btn)

        self._pull_btn = QPushButton("⬇  Pull Panic Logs")
        self._pull_btn.setStyleSheet(self._BTN_QSS)
        self._pull_btn.setEnabled(False)
        self._pull_btn.clicked.connect(self._on_pull)
        lay.addWidget(self._pull_btn)

        # Tool status dot
        self._tool_status = QLabel()
        self._tool_status.setStyleSheet("font-size:10px;")
        self._tool_status.setToolTip("libimobiledevice tool status")
        lay.addWidget(self._tool_status)

        if manager is not None and _DM_AVAILABLE:
            manager.device_connected.connect(self._refresh)
            manager.device_disconnected.connect(self._refresh)

        self._refresh()
        self._check_tools()

    def _check_tools(self) -> None:
        """Update the tool-status dot based on available libimobiledevice tools."""
        if not _PANIC_PULL_AVAILABLE:
            self._tool_status.setText("⚠")
            self._tool_status.setToolTip("apple_panic_pull not loaded")
            return
        statuses = check_tools(_TOOLS_DIR)
        have_crash = any(s.name == "idevicecrashreport" and s.available for s in statuses)
        have_id    = any(s.name == "idevice_id"         and s.available for s in statuses)
        if have_crash and have_id:
            self._tool_status.setText("🟢")
            tip = "libimobiledevice: idevicecrashreport + idevice_id found"
        elif have_crash:
            self._tool_status.setText("🟡")
            tip = "idevicecrashreport found; idevice_id missing (device list may be limited)"
        else:
            self._tool_status.setText("🔴")
            tip = (
                "libimobiledevice tools not found.\n"
                + install_instructions()
            )
        self._tool_status.setToolTip(tip)

    def _refresh(self, *_args) -> None:
        self._combo.clear()
        self._known_devices = []

        # Try apple_panic_pull's device list first (idevice_id)
        if _PANIC_PULL_AVAILABLE:
            try:
                devices = list_connected_devices(_TOOLS_DIR)
                for dev in devices:
                    label = f"{dev.display_name}  [{dev.udid[:12]}…]"
                    if dev.ios_version:
                        label += f"  iOS {dev.ios_version}"
                    self._combo.addItem(label, userData=dev.udid)
                    self._known_devices.append(dev)
            except Exception as exc:
                log.warning("apple_panic_pull device discovery failed: %s", exc)

        # Fall back to DeviceManager if needed
        if not self._known_devices and self._manager is not None and _DM_AVAILABLE:
            if DevicePlatform is not None:
                for dev in self._manager.devices:
                    if dev.platform == DevicePlatform.APPLE:
                        label = f"{dev.display_name}  [{dev.serial[:12]}]"
                        self._combo.addItem(label, userData=dev.serial)
                        self._known_devices.append(dev)

        has = bool(self._known_devices)
        self._pull_btn.setEnabled(has)
        if not has:
            self._combo.setPlaceholderText("No Apple devices — connect & trust device")

    def _on_pull(self) -> None:
        udid = self._combo.currentData()
        if udid:
            self.pull_requested.emit(udid)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — RAW LOG SYNTAX HIGHLIGHTER
# ═══════════════════════════════════════════════════════════════════════════

class PanicHighlighter(QSyntaxHighlighter):
    """Highlights panic keywords in the raw log preview pane."""

    _RULES: list[tuple[str, str]] = [
        (r"panic\(cpu[^)]*\)", "#FF5555"),
        (r"NAND|AppleNAND|NVMe|ANS\d", "#F38BA8"),
        (r"battery|PMIC|PMU|UVLO|gasgauge", "#FAB387"),
        (r"Face ID|SEP|SecureEnclave|TrueDepth|Biometric", "#CBA6F7"),
        (r"TCON|DCP|backlight|display|MIPI", "#89DCEB"),
        (r"Tristar|Hydra|ACE|USBC|charging|lightning", "#F9E2AF"),
        (r"audio|Cirrus|TAS\d+|HDA|codec|speaker", "#A6E3A1"),
        (r"baseband|wwan|modem|XMM|QSC|MDM", "#94E2D5"),
        (r"Kernel version:|iBoot version:|BSD process|Panicked task", "#6C7086"),
        (r">>>[^:]*:", "#CBA6F7"),          # context marker
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._formats: list[tuple[__import__("re").Pattern, QTextCharFormat]] = []
        import re
        for pattern, color in self._RULES:
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            fmt.setFontWeight(QFont.Weight.Bold)
            self._formats.append((re.compile(pattern, re.I), fmt))

    def highlightBlock(self, text: str) -> None:
        for pat, fmt in self._formats:
            for m in pat.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — MAIN PAGE
# ═══════════════════════════════════════════════════════════════════════════

class AppleAnalysisPageFull(QWidget):
    """
    Full Apple panic-log analysis page.
    Compatible with BasePage contract (page_id, _title, status_message,
    on_activated, on_deactivated).
    """
    page_id = "apple_analysis"
    _title  = "Apple Analysis"

    from PyQt6.QtCore import pyqtSignal as _sig
    status_message = _sig(str, int)

    def __init__(self, parent: QWidget | None = None,
                 device_manager: "DeviceManager | None" = None) -> None:
        super().__init__(parent)
        self.setObjectName("ApplePage")
        self.setStyleSheet(_BASE_QSS)
        self._result: AppleAnalysisResult | None = None
        self._device_manager = device_manager
        self._apple_picker: AppleDevicePicker | None = None
        self._build_ui()

        # Show device picker whenever apple_panic_pull is available
        # (does NOT require DeviceManager — uses idevice_id directly)
        if _PANIC_PULL_AVAILABLE or (device_manager is not None and _DM_AVAILABLE):
            self._apple_picker = AppleDevicePicker(
                manager=device_manager if _DM_AVAILABLE else None
            )
            self._apple_picker.pull_requested.connect(self._pull_from_device)
            self._header_action_layout.insertWidget(0, self._apple_picker)

    # ── UI Construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Page Header ──────────────────────────────────────────────────
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

        txt = QVBoxLayout()
        txt.setSpacing(1)
        t = QLabel("Apple Analysis")
        t.setObjectName("PageTitle")
        txt.addWidget(t)
        s = QLabel("iPhone panic log analysis — panic-full · panic-base · .ips · sysdiagnose")
        s.setObjectName("PageSub")
        txt.addWidget(s)
        h_lay.addLayout(txt)
        h_lay.addStretch()

        self._header_action_layout = QHBoxLayout()
        self._header_action_layout.setSpacing(6)

        self._open_btn = QPushButton("📂  Open Panic Log")
        self._open_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._open_btn.clicked.connect(self._open_dialog)
        self._header_action_layout.addWidget(self._open_btn)

        self._export_btn = QPushButton("⬇  Export Report")
        self._export_btn.setStyleSheet(_ACTION_BTN_QSS)
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._export_report)
        self._header_action_layout.addWidget(self._export_btn)

        h_lay.addLayout(self._header_action_layout)
        root.addWidget(header)

        # ── Progress bar (hidden by default) ─────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)   # indeterminate
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._progress.setStyleSheet(
            "QProgressBar{background:#181825;border:none;}"
            "QProgressBar::chunk{background:#CBA6F7;}"
        )
        root.addWidget(self._progress)

        # ── Content area (stacked) ────────────────────────────────────────
        content = QWidget()
        content.setObjectName("PageContent")
        content.setStyleSheet("QWidget#PageContent{background:#1E1E2E;}")
        c_lay = QVBoxLayout(content)
        c_lay.setContentsMargins(20, 16, 20, 16)
        c_lay.setSpacing(12)

        self._stack = QStackedWidget()

        # Page 0: Drop zone
        drop_page = QWidget()
        dp_lay = QVBoxLayout(drop_page)
        dp_lay.setContentsMargins(0, 0, 0, 0)
        self._drop_zone = DropZone()
        self._drop_zone.file_dropped.connect(self._load_file)
        dp_lay.addWidget(self._drop_zone)
        self._stack.addWidget(drop_page)

        # Page 1: Results
        results_page = QWidget()
        rp_lay = QVBoxLayout(results_page)
        rp_lay.setContentsMargins(0, 0, 0, 0)
        rp_lay.setSpacing(10)

        # Summary bar
        summary_bar = QHBoxLayout()
        summary_bar.setSpacing(8)
        self._chip_file     = _summary_chip("File",     "—", "#CBA6F7", wide=True)
        self._chip_source   = _summary_chip("Source",   "—", "#89B4FA", wide=True)
        self._chip_critical = _summary_chip("Critical", "0", "#FF5555")
        self._chip_high     = _summary_chip("High",     "0", "#FF8C00")
        self._chip_medium   = _summary_chip("Medium",   "0", "#FFD700")
        self._chip_low      = _summary_chip("Low",      "0", "#87CEEB")
        for chip in [self._chip_file, self._chip_source, self._chip_critical,
                     self._chip_high, self._chip_medium, self._chip_low]:
            summary_bar.addWidget(chip)
        summary_bar.addStretch()

        back_btn = QPushButton("← New Analysis")
        back_btn.setStyleSheet(_ACTION_BTN_QSS)
        back_btn.clicked.connect(lambda: self._stack.setCurrentIndex(0))
        summary_bar.addWidget(back_btn)
        rp_lay.addLayout(summary_bar)

        # Device info strip (populated when available)
        self._device_strip = QLabel("")
        self._device_strip.setStyleSheet(
            "color:#6C7086;font-size:11px;background:#181825;"
            "border:1px solid #313244;border-radius:6px;padding:6px 12px;"
        )
        self._device_strip.setWordWrap(True)
        self._device_strip.hide()
        rp_lay.addWidget(self._device_strip)

        # Splitter: findings | raw log
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;}")

        # Left: findings
        findings_container = QWidget()
        findings_container.setStyleSheet("background:#1E1E2E;")
        fc_lay = QVBoxLayout(findings_container)
        fc_lay.setContentsMargins(0, 0, 6, 0)
        fc_lay.setSpacing(0)

        fl = QLabel("Findings")
        fl.setStyleSheet("color:#CDD6F4;font-size:12px;font-weight:600;padding:0 0 8px 0;")
        fc_lay.addWidget(fl)

        self._findings_scroll  = QScrollArea()
        self._findings_scroll.setWidgetResizable(True)
        self._findings_scroll.setStyleSheet("QScrollArea{border:none;background:#1E1E2E;}")
        self._findings_inner   = QWidget()
        self._findings_inner.setStyleSheet("background:#1E1E2E;")
        self._findings_layout  = QVBoxLayout(self._findings_inner)
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

        rl = QLabel("Raw Log Preview (first 120 lines)")
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
        self._highlighter = PanicHighlighter(self._raw_log.document())
        rc_lay.addWidget(self._raw_log, stretch=1)
        splitter.addWidget(raw_container)

        splitter.setSizes([580, 420])
        rp_lay.addWidget(splitter, stretch=1)
        self._stack.addWidget(results_page)

        # Page 2: Not a panic log
        skip_page = QWidget()
        sp_lay = QVBoxLayout(skip_page)
        sp_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_lay.setSpacing(12)
        sp_icon = QLabel("🍎")
        sp_icon.setStyleSheet("font-size:48px;")
        sp_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_msg = QLabel(
            "This file does not appear to be an Apple panic log.\n"
            "Supported formats: panic-full · panic-base · .ips analytics · sysdiagnose bundle\n\n"
            "Try opening a .ips file, .panic file, or a sysdiagnose .tar.gz archive."
        )
        sp_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sp_msg.setStyleSheet("color:#6C7086;font-size:13px;")
        back2 = QPushButton("← Try Another File")
        back2.setStyleSheet(_ACTION_BTN_QSS)
        back2.setFixedWidth(200)
        back2.clicked.connect(lambda: self._stack.setCurrentIndex(0))
        sp_lay.addWidget(sp_icon)
        sp_lay.addWidget(sp_msg)
        sp_lay.addWidget(back2, alignment=Qt.AlignmentFlag.AlignCenter)
        self._stack.addWidget(skip_page)

        c_lay.addWidget(self._stack, stretch=1)
        root.addWidget(content, stretch=1)

        self._stack.setCurrentIndex(0)

    # ── Chip helpers ──────────────────────────────────────────────────────

    def _update_chip(self, chip: QFrame, value: str) -> None:
        for child in chip.findChildren(QLabel, "ChipValue"):
            child.setText(value)

    # ── Device pull ───────────────────────────────────────────────────────

    def _pull_from_device(self, udid: str) -> None:
        self.status_message.emit(f"Pulling panic logs from {udid[:12]}…", 0)
        self._progress.show()
        self._open_btn.setEnabled(False)
        if self._apple_picker:
            self._apple_picker.setEnabled(False)

        worker = _PullWorker(udid, _TOOLS_DIR)
        worker.signals.progress.connect(
            lambda msg: self.status_message.emit(msg, 0)
        )
        worker.signals.finished.connect(self._on_pull_result)
        worker.signals.error.connect(self._on_pull_error)
        QThreadPool.globalInstance().start(worker)

    def _on_pull_result(self, text: str, source: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        if self._apple_picker:
            self._apple_picker.setEnabled(True)
        self.status_message.emit(f"Analysing pulled panic logs…", 0)
        self._progress.show()
        worker = _AnalysisWorker(text=text, filename=source,
                                 source_hint=AppleSourceType.PANIC_FULL)
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        QThreadPool.globalInstance().start(worker)

    def _on_pull_error(self, msg: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        if self._apple_picker:
            self._apple_picker.setEnabled(True)
        self.status_message.emit(f"Pull failed: {msg}", 8000)
        log.error("Apple pull error: %s", msg)

    # ── File open ─────────────────────────────────────────────────────────

    def _open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Apple Panic Log", "",
            "Panic logs (*.ips *.panic *.txt *.log *.gz *.tgz *.zip);;All files (*)",
        )
        if path:
            self._load_file(Path(path))

    def _load_file(self, path: Path) -> None:
        if not path.exists():
            self.status_message.emit(f"File not found: {path.name}", 4000)
            return

        size_mib = path.stat().st_size / (1024 * 1024)
        if size_mib > 256:
            self.status_message.emit(
                f"File too large ({size_mib:.0f} MiB > 256 MiB limit)", 5000
            )
            return

        self.status_message.emit(f"Analysing {path.name}…", 0)
        self._progress.show()
        self._open_btn.setEnabled(False)

        QTimer.singleShot(0, lambda: self._start_analysis(path))

    def _start_analysis(self, path: Path) -> None:
        try:
            analyzer = ApplePanicAnalyzer()
            text, fname, source_hint = analyzer._read_file(path)
        except Exception as exc:
            self._on_error(str(exc))
            return

        worker = _AnalysisWorker(
            text=text, filename=fname, source_hint=source_hint
        )
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        QThreadPool.globalInstance().start(worker)

    # ── Result handler ────────────────────────────────────────────────────

    def _on_result(self, result: AppleAnalysisResult) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        self._result = result

        if not result.is_panic_log:
            self._stack.setCurrentIndex(2)
            self.status_message.emit("File not recognised as Apple panic log", 5000)
            return

        # Summary chips
        fname = result.file_name
        self._update_chip(
            self._chip_file,
            (fname[:18] + "…") if len(fname) > 18 else fname
        )
        self._update_chip(self._chip_source, result.source_type.value)

        sev_counts = {s: 0 for s in Severity}
        for f in result.findings:
            sev_counts[f.severity] += 1
        self._update_chip(self._chip_critical, str(sev_counts[Severity.CRITICAL]))
        self._update_chip(self._chip_high,     str(sev_counts[Severity.HIGH]))
        self._update_chip(self._chip_medium,   str(sev_counts[Severity.MEDIUM]))
        self._update_chip(self._chip_low,      str(sev_counts[Severity.LOW]))

        # Device info strip
        if result.device_info:
            parts = [f"<b>{k}:</b> {v}" for k, v in result.device_info.items()]
            self._device_strip.setText("  ·  ".join(parts))
            self._device_strip.show()
        else:
            self._device_strip.hide()

        # Raw log
        self._raw_log.setPlainText(result.raw_preview)

        # Findings cards (clear old ones)
        while self._findings_layout.count() > 1:
            item = self._findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if result.findings:
            for i, finding in enumerate(result.findings, 1):
                card = FindingCard(finding, i)
                self._findings_layout.insertWidget(i - 1, card)
        else:
            no_find = QLabel("✅ No hardware fault signatures found above the confidence threshold.")
            no_find.setStyleSheet("color:#50FA7B;font-size:12px;padding:16px;")
            no_find.setAlignment(Qt.AlignmentFlag.AlignCenter)
            no_find.setWordWrap(True)
            self._findings_layout.insertWidget(0, no_find)

        self._export_btn.setEnabled(True)
        self._stack.setCurrentIndex(1)

        n = len(result.findings)
        self.status_message.emit(
            f"Analysis complete — {n} finding{'s' if n != 1 else ''} in {result.file_name}",
            5000,
        )

    def _on_error(self, msg: str) -> None:
        self._progress.hide()
        self._open_btn.setEnabled(True)
        self.status_message.emit(f"Analysis error: {msg}", 8000)
        log.error("Apple analysis error: %s", msg)

    # ── Export ────────────────────────────────────────────────────────────

    def _export_report(self) -> None:
        if not self._result:
            return
        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Report", f"paniclab_{self._result.file_name}_report",
            "HTML report (*.html);;Markdown report (*.md)",
        )
        if not path:
            return
        try:
            if path.endswith(".md"):
                text = format_markdown_report(self._result)
                Path(path).write_text(text, encoding="utf-8")
            else:
                html = format_html_report(self._result)
                Path(path).write_text(html, encoding="utf-8")
            self.status_message.emit(f"Report exported → {Path(path).name}", 5000)
        except Exception as exc:
            self.status_message.emit(f"Export failed: {exc}", 8000)

    # ── BasePage lifecycle ────────────────────────────────────────────────

    def on_activated(self)   -> None: pass
    def on_deactivated(self) -> None: pass
