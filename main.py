"""
PanicLab — iPhone panic log & Android kernel crash analyzer
===========================================================
Run with:  python main.py
Requires:  pip install PyQt6 pydantic platformdirs pyqtdarktheme
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Annotated, Callable, Literal

# ── Dependency check ────────────────────────────────────────────────────────
try:
    from PyQt6.QtCore import QMimeData, QSize, Qt, QTimer, pyqtSignal
    from PyQt6.QtGui import QAction, QDragEnterEvent, QDragLeaveEvent, QDropEvent, QKeySequence
    from PyQt6.QtWidgets import (
        QApplication, QButtonGroup, QFileDialog, QFrame, QGridLayout,
        QHBoxLayout, QLabel, QMainWindow, QMessageBox, QProgressBar,
        QPushButton, QSizePolicy, QStackedWidget, QStatusBar, QVBoxLayout,
        QWidget,
    )
except ImportError:
    print("PyQt6 is not installed.\nRun:  pip install PyQt6 pydantic platformdirs pyqtdarktheme")
    sys.exit(1)

try:
    from pydantic import BaseModel, Field, field_validator
    from platformdirs import user_config_dir, user_data_dir, user_log_dir
except ImportError:
    print("Missing deps.\nRun:  pip install pydantic platformdirs")
    sys.exit(1)

__version__ = "0.1.0"
APP_NAME    = "PanicLab"

# ── DeviceManager ────────────────────────────────────────────────────────────
try:
    from device_manager import DeviceManager, DevicesPageFull
    _DEVICE_MANAGER_AVAILABLE = True
except ImportError:
    _DEVICE_MANAGER_AVAILABLE = False
    DeviceManager   = None   # type: ignore[assignment,misc]
    DevicesPageFull = None   # type: ignore[assignment]

# ── Android Analyzer ─────────────────────────────────────────────────────────
try:
    from android_analysis_page import AndroidAnalysisPageFull
    _ANDROID_ANALYZER_AVAILABLE = True
except ImportError:
    _ANDROID_ANALYZER_AVAILABLE = False
    AndroidAnalysisPageFull = None  # type: ignore[assignment,misc]

# ── Apple Analyzer ───────────────────────────────────────────────────────────
try:
    from apple_analysis_page import AppleAnalysisPageFull
    _APPLE_ANALYZER_AVAILABLE = True
except ImportError:
    _APPLE_ANALYZER_AVAILABLE = False
    AppleAnalysisPageFull = None  # type: ignore[assignment,misc]

# ── Battery Health Analyzer ──────────────────────────────────────────────────
try:
    from battery_health_page import BatteryHealthPageFull
    _BATTERY_HEALTH_AVAILABLE = True
except ImportError:
    _BATTERY_HEALTH_AVAILABLE = False
    BatteryHealthPageFull = None  # type: ignore[assignment,misc]

# ── Directories ──────────────────────────────────────────────────────────────
CONFIG_DIR = Path(user_config_dir(APP_NAME))
LOG_DIR    = Path(user_log_dir(APP_NAME))
for _d in (CONFIG_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = CONFIG_DIR / "config.json"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONFIG
# ═══════════════════════════════════════════════════════════════════════════

class AnalysisConfig(BaseModel):
    min_confidence:           Annotated[int, Field(ge=0, le=100)] = 40
    context_lines:            Annotated[int, Field(ge=0, le=50)]  = 5
    enable_battery_analysis:  bool = True
    enable_hardware_analysis: bool = True
    max_file_size_mib:        Annotated[int, Field(ge=1, le=2048)] = 256

class UIConfig(BaseModel):
    theme:              Literal["dark", "light", "system"] = "dark"
    window_geometry:    str       = ""
    log_font_size:      Annotated[int, Field(ge=8, le=32)] = 13
    side_panel_visible: bool      = True
    recent_files:       list[str] = Field(default_factory=list)

    @field_validator("recent_files")
    @classmethod
    def _cap(cls, v: list[str]) -> list[str]:
        return v[:20]

class ReportConfig(BaseModel):
    output_format:        Literal["markdown", "html", "pdf"] = "html"
    include_raw_snippets: bool = True
    default_output_dir:   str  = ""

class AppConfig(BaseModel):
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    ui:       UIConfig       = Field(default_factory=UIConfig)
    report:   ReportConfig   = Field(default_factory=ReportConfig)
    model_config = {"validate_assignment": True}

    def save(self) -> None:
        try:
            CONFIG_FILE.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        except OSError as e:
            logging.getLogger(__name__).error("Config save failed: %s", e)

    @classmethod
    def load(cls) -> "AppConfig":
        if not CONFIG_FILE.exists():
            return cls()
        try:
            return cls.model_validate(json.loads(CONFIG_FILE.read_text("utf-8")))
        except Exception:
            return cls()

    def add_recent_file(self, path: str | Path) -> None:
        p = str(path)
        self.ui.recent_files = [p, *[f for f in self.ui.recent_files if f != p]][:20]
        self.save()

_cfg: AppConfig | None = None
def get_config() -> AppConfig:
    global _cfg
    if _cfg is None:
        _cfg = AppConfig.load()
    return _cfg

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — THEME
# ═══════════════════════════════════════════════════════════════════════════

class SeverityColor(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    OK       = "ok"

@dataclass(frozen=True)
class ThemePalette:
    mode:             str
    severity:         dict[SeverityColor, str] = field(default_factory=dict)
    card_background:  str = "#1E1E2E"
    card_border:      str = "#313244"
    accent:           str = "#CBA6F7"
    log_keyword_panic:str = "#FF5555"

DARK_PALETTE = ThemePalette(
    mode="dark",
    severity={
        SeverityColor.CRITICAL: "#FF5555",
        SeverityColor.HIGH:     "#FF8C00",
        SeverityColor.MEDIUM:   "#FFD700",
        SeverityColor.LOW:      "#87CEEB",
        SeverityColor.OK:       "#50FA7B",
    },
    card_background="#1E1E2E",
    card_border="#313244",
    accent="#CBA6F7",
)

LIGHT_PALETTE = ThemePalette(
    mode="light",
    severity={
        SeverityColor.CRITICAL: "#CC0000",
        SeverityColor.HIGH:     "#D45000",
        SeverityColor.MEDIUM:   "#B8860B",
        SeverityColor.LOW:      "#1565C0",
        SeverityColor.OK:       "#2E7D32",
    },
    card_background="#F5F5F5",
    card_border="#E0E0E0",
    accent="#7B1FA2",
)

_active_palette: ThemePalette = DARK_PALETTE

def get_palette() -> ThemePalette:
    return _active_palette

def _build_qss(p: ThemePalette) -> str:
    sev = p.severity
    return f"""
QLabel[severity="critical"] {{ color:{sev[SeverityColor.CRITICAL]}; font-weight:bold; }}
QLabel[severity="high"]     {{ color:{sev[SeverityColor.HIGH]};     font-weight:bold; }}
QLabel[severity="medium"]   {{ color:{sev[SeverityColor.MEDIUM]}; }}
QLabel[severity="low"]      {{ color:{sev[SeverityColor.LOW]}; }}
QLabel[severity="ok"]       {{ color:{sev[SeverityColor.OK]}; }}
QFrame[role="finding-card"] {{
    background:{p.card_background}; border:1px solid {p.card_border};
    border-radius:6px; padding:8px;
}}
QFrame[role="finding-card"]:hover {{ border-color:{p.accent}; }}
QTabBar::tab:selected {{ border-bottom:2px solid {p.accent}; }}
QProgressBar {{ border-radius:4px; text-align:center; height:14px; }}
QScrollBar:vertical {{ width:8px; margin:0; }}
QScrollBar::handle:vertical {{ border-radius:4px; min-height:20px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
"""

def apply_theme(app: QApplication, mode: str = "dark") -> None:
    """
    Apply qdarktheme, handling both package variants gracefully:

      pyqtdarktheme-fork  (recommended) — has setup_theme()
          pip install pyqtdarktheme-fork

      pyqtdarktheme 1.x   (legacy/abandoned) — only has load_stylesheet()
          pip install pyqtdarktheme

    If neither is installed the app falls back to the plain Qt palette.
    """
    global _active_palette
    _log  = logging.getLogger(__name__)
    _mode = mode if mode in ("dark", "light") else "dark"   # guard "system"

    try:
        import qdarktheme

        if hasattr(qdarktheme, "setup_theme"):
            # pyqtdarktheme-fork ≥ 2.x
            qdarktheme.setup_theme(
                theme=_mode,
                custom_colors={
                    "[dark]":  {"primary": DARK_PALETTE.accent,
                                "background>base": "#1E1E2E"},
                    "[light]": {"primary": LIGHT_PALETTE.accent},
                },
            )
        elif hasattr(qdarktheme, "load_stylesheet"):
            # pyqtdarktheme 1.x — no custom_colors, no setup_theme
            app.setStyleSheet(qdarktheme.load_stylesheet(_mode))
            if hasattr(qdarktheme, "load_palette"):
                app.setPalette(qdarktheme.load_palette(_mode))
            _log.info(
                "pyqtdarktheme 1.x detected — upgrade to pyqtdarktheme-fork "
                "for full colour customisation:  "
                "pip install pyqtdarktheme-fork"
            )
        else:
            _log.warning("qdarktheme module found but no known API — skipping theme.")

    except ImportError:
        _log.warning(
            "qdarktheme not installed — using default Qt palette.  "
            "Run:  pip install pyqtdarktheme-fork"
        )

    _active_palette = DARK_PALETTE if _mode != "light" else LIGHT_PALETTE
    app.setStyleSheet(app.styleSheet() + _build_qss(_active_palette))

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class NavItem:
    page_id: str
    label:   str
    icon:    str
    tooltip: str = ""

NAV_ITEMS: list[NavItem] = [
    NavItem("dashboard",        "Dashboard", "🏠", "Overview & recent activity"),
    NavItem("devices",          "Devices",   "📱", "Manage analysed devices"),
    NavItem("apple_analysis",   "Apple",     "🍎", "iPhone panic log analysis"),
    NavItem("android_analysis", "Android",   "🤖", "Android kernel crash analysis"),
    NavItem("battery_health",   "Battery",   "🔋", "Battery health scoring"),
    NavItem("reports",          "Reports",   "📋", "Generated repair reports"),
    NavItem("settings",         "Settings",  "⚙️",  "Application settings"),
]

_NAV_BTN_QSS = """
QPushButton {{
    background:transparent; border:none; border-radius:8px;
    color:{fg_inactive}; font-size:12px; padding:0; text-align:left;
}}
QPushButton:hover   {{ background:{hover_bg};       color:{fg_active}; }}
QPushButton:checked {{ background:{active_bg};      color:{fg_active}; font-weight:600; }}
QPushButton:checked:hover {{ background:{active_bg_hover}; }}
"""

class NavButton(QPushButton):
    def __init__(self, item: NavItem, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._item = item
        self.setCheckable(True)
        self.setToolTip(item.tooltip or item.label)
        self.setFixedHeight(64)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(_NAV_BTN_QSS.format(
            fg_inactive="#6C7086", fg_active="#CDD6F4",
            hover_bg="rgba(203,166,247,0.08)", active_bg="rgba(203,166,247,0.18)",
            active_bg_hover="rgba(203,166,247,0.22)",
        ))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 6)
        lay.setSpacing(2)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_l = QLabel(item.icon)
        icon_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_l.setStyleSheet("font-size:20px; background:transparent; border:none;")
        text_l = QLabel(item.label)
        text_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text_l.setStyleSheet(
            "font-size:9px; font-weight:500; background:transparent; "
            "border:none; letter-spacing:0.5px;"
        )
        lay.addWidget(icon_l)
        lay.addWidget(text_l)

    @property
    def page_id(self) -> str:
        return self._item.page_id

class Sidebar(QWidget):
    page_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(80)
        self.setStyleSheet("QWidget#Sidebar{background:#181825;border-right:1px solid #313244;}")
        self._buttons: dict[str, NavButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Logo
        logo_area = QWidget()
        logo_area.setFixedHeight(72)
        ll = QVBoxLayout(logo_area)
        ll.setContentsMargins(0, 12, 0, 8)
        ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo = QLabel("🔬")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("color:#CBA6F7; font-size:26px; font-weight:700;")
        ver = QLabel(f"v{__version__}")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color:#45475A; font-size:9px;")
        ll.addWidget(logo)
        ll.addWidget(ver)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#313244;")
        sep.setFixedHeight(1)
        root.addWidget(logo_area)
        root.addWidget(sep)

        # Nav buttons
        nav_w = QWidget()
        nav_l = QVBoxLayout(nav_w)
        nav_l.setContentsMargins(6, 8, 6, 8)
        nav_l.setSpacing(2)
        for item in NAV_ITEMS:
            btn = NavButton(item)
            self._buttons[item.page_id] = btn
            self._group.addButton(btn)
            btn.clicked.connect(self._on_click)
            nav_l.addWidget(btn)
        root.addWidget(nav_w)
        root.addStretch()

        bot_sep = QFrame()
        bot_sep.setFrameShape(QFrame.Shape.HLine)
        bot_sep.setStyleSheet("color:#313244;")
        bot_sep.setFixedHeight(1)
        hint = QLabel("PanicLab")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color:#313244; font-size:8px; padding:6px 0;")
        root.addWidget(bot_sep)
        root.addWidget(hint)

        self.set_active_page(NAV_ITEMS[0].page_id)

    def set_active_page(self, page_id: str) -> None:
        if btn := self._buttons.get(page_id):
            btn.setChecked(True)

    def _on_click(self) -> None:
        if isinstance(s := self.sender(), NavButton):
            self.page_requested.emit(s.page_id)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — STATUS BAR
# ═══════════════════════════════════════════════════════════════════════════

class AppStatusBar(QStatusBar):
    _QSS = """
    QStatusBar { background:#11111B; border-top:1px solid #313244; color:#6C7086; font-size:11px; }
    QStatusBar::item { border:none; }
    QLabel#StatusMain  { color:#CDD6F4; padding:0 8px; }
    QLabel#StatusRight { color:#6C7086; padding:0 8px; font-size:10px; }
    QLabel#DropHint    { color:#45475A; padding:0 8px; font-size:10px; }
    QLabel#DropHint[active="true"] { color:#CBA6F7; }
    QProgressBar#StatusProgress {
        max-width:120px; max-height:8px; border-radius:4px; background:#313244;
    }
    QProgressBar#StatusProgress::chunk { background:#CBA6F7; border-radius:4px; }
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSizeGripEnabled(True)
        self.setStyleSheet(self._QSS)
        self._default_msg = "Ready"

        self._main_lbl = QLabel("Ready")
        self._main_lbl.setObjectName("StatusMain")
        self.addWidget(self._main_lbl, stretch=1)

        self._progress = QProgressBar()
        self._progress.setObjectName("StatusProgress")
        self._progress.setRange(0, 100)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self.addWidget(self._progress)

        self._drop_hint = QLabel("Drop log files to analyse")
        self._drop_hint.setObjectName("DropHint")
        self._drop_hint.setProperty("active", "false")
        self.addPermanentWidget(self._drop_hint)

        self._right_lbl = QLabel("No file loaded")
        self._right_lbl.setObjectName("StatusRight")
        self.addPermanentWidget(self._right_lbl)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(lambda: self._main_lbl.setText(self._default_msg))

    def show_message(self, text: str, timeout_ms: int = 4000) -> None:
        self._main_lbl.setText(text)
        if timeout_ms > 0:
            self._timer.start(timeout_ms)

    def set_context(self, text: str) -> None:
        self._right_lbl.setText(text)

    def show_progress(self, value: int, maximum: int = 100) -> None:
        self._progress.setMaximum(maximum)
        self._progress.setValue(value)
        self._progress.show()

    def hide_progress(self) -> None:
        self._progress.hide()
        self._progress.reset()

    def set_drop_active(self, active: bool) -> None:
        self._drop_hint.setProperty("active", "true" if active else "false")
        self._drop_hint.style().unpolish(self._drop_hint)
        self._drop_hint.style().polish(self._drop_hint)
        self._drop_hint.setText("Release to analyse" if active else "Drop log files to analyse")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — BASE PAGE
# ═══════════════════════════════════════════════════════════════════════════

_CARD_QSS = """
QFrame[role="card"] {
    background:#181825; border:1px solid #313244; border-radius:8px;
}
"""

class BasePage(QWidget):
    page_id        = "base"
    status_message = pyqtSignal(str, int)

    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._title = title
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
        txt = QVBoxLayout()
        txt.setSpacing(1)
        t = QLabel(title)
        t.setObjectName("PageTitle")
        txt.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setObjectName("PageSub")
            txt.addWidget(s)
        h_lay.addLayout(txt)
        h_lay.addStretch()
        self._action_layout = QHBoxLayout()
        self._action_layout.setSpacing(6)
        h_lay.addLayout(self._action_layout)
        root.addWidget(header)

        # Content
        content = QWidget()
        content.setObjectName("PageContent")
        content.setStyleSheet("QWidget#PageContent{background:#1E1E2E;}")
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(20, 16, 20, 16)
        self._content_layout.setSpacing(12)
        root.addWidget(content, stretch=1)

    def add_header_action(self, btn: QPushButton) -> None:
        btn.setStyleSheet(
            "QPushButton{min-height:28px;padding:0 12px;border-radius:6px;"
            "background:#313244;color:#CDD6F4;font-size:11px;}"
            "QPushButton:hover{background:#45475A;}"
        )
        self._action_layout.addWidget(btn)

    def add_placeholder(self, icon: str, message: str) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        il = QLabel(icon)
        il.setStyleSheet("font-size:48px;color:#313244;")
        il.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ml = QLabel(message)
        ml.setStyleSheet("font-size:13px;color:#45475A;")
        ml.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(il)
        lay.addWidget(ml)
        self._content_layout.addStretch()
        self._content_layout.addWidget(w)
        self._content_layout.addStretch()

    def on_activated(self)   -> None: pass
    def on_deactivated(self) -> None: pass

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — PAGES  (stubs — replaced by Full variants when available)
# ═══════════════════════════════════════════════════════════════════════════

def _make_card(title: str, value: str, icon: str, colour: str = "#CBA6F7") -> QFrame:
    card = QFrame()
    card.setProperty("role", "card")
    card.setStyleSheet(_CARD_QSS)
    card.setFixedHeight(90)
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 10, 14, 10)
    lay.setSpacing(4)
    top = QHBoxLayout()
    il = QLabel(icon)
    il.setStyleSheet(f"font-size:18px;color:{colour};")
    tl = QLabel(title)
    tl.setStyleSheet("font-size:10px;color:#6C7086;font-weight:500;")
    top.addWidget(il)
    top.addWidget(tl)
    top.addStretch()
    vl = QLabel(value)
    vl.setStyleSheet(f"font-size:22px;font-weight:700;color:{colour};")
    lay.addLayout(top)
    lay.addWidget(vl)
    return card

def _drop_zone(icon: str, text: str) -> QFrame:
    zone = QFrame()
    zone.setStyleSheet(
        "QFrame{background:#181825;border:2px dashed #313244;border-radius:12px;}"
    )
    zone.setMinimumHeight(160)
    lay = QVBoxLayout(zone)
    lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.setSpacing(8)
    il = QLabel(icon)
    il.setStyleSheet("font-size:40px;")
    il.setAlignment(Qt.AlignmentFlag.AlignCenter)
    ml = QLabel(text)
    ml.setStyleSheet("color:#6C7086;font-size:12px;")
    ml.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(il)
    lay.addWidget(ml)
    return zone


class DashboardPage(BasePage):
    page_id = "dashboard"
    def __init__(self, parent=None):
        super().__init__("Dashboard", "Overview & recent activity", parent)
        grid = QGridLayout()
        grid.setSpacing(12)
        grid.addWidget(_make_card("Logs Analysed",    "0", "📂", "#CBA6F7"), 0, 0)
        grid.addWidget(_make_card("Critical Issues",  "0", "🔴", "#FF5555"), 0, 1)
        grid.addWidget(_make_card("Devices Tracked",  "0", "📱", "#8BE9FD"), 0, 2)
        grid.addWidget(_make_card("Reports Generated","0", "📋", "#50FA7B"), 0, 3)
        self._content_layout.addLayout(grid)

        recent = QFrame()
        recent.setProperty("role", "card")
        recent.setStyleSheet(_CARD_QSS)
        rl = QVBoxLayout(recent)
        rl.setContentsMargins(14, 12, 14, 12)
        rl.addWidget(QLabel("Recent Activity", styleSheet="font-size:13px;font-weight:600;color:#CDD6F4;"))
        empty = QLabel("No logs analysed yet.\nDrag and drop a panic log or bugreport to get started.")
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.setStyleSheet("color:#45475A;font-size:12px;padding:24px 0;")
        rl.addWidget(empty)
        self._content_layout.addWidget(recent, stretch=1)

        acts = QHBoxLayout()
        for label, icon in [("Open File", "📂"), ("Import Device", "📱"), ("View Reports", "📋")]:
            btn = QPushButton(f"{icon}  {label}")
            btn.setStyleSheet(
                "QPushButton{background:#313244;color:#CDD6F4;border-radius:6px;"
                "padding:8px 18px;font-size:12px;} QPushButton:hover{background:#45475A;}"
            )
            acts.addWidget(btn)
        acts.addStretch()
        self._content_layout.addLayout(acts)


class DevicesPage(BasePage):
    page_id = "devices"
    def __init__(self, parent=None):
        super().__init__("Devices", "Manage analysed devices", parent)
        self.add_header_action(QPushButton("＋  Add Device"))
        self.add_placeholder("📱", "No devices tracked yet.\nAnalyse a log to add a device automatically.")


class AppleAnalysisPage(BasePage):
    page_id = "apple_analysis"
    def __init__(self, parent=None):
        super().__init__("Apple Analysis", "iPhone panic log analysis", parent)
        self.add_header_action(QPushButton("📂  Open .ips / .panic"))
        self._content_layout.addWidget(_drop_zone("🍎", "Drop iPhone panic logs here (.ips, .panic, .txt)"))
        self._content_layout.addStretch()


class AndroidAnalysisPage(BasePage):
    page_id = "android_analysis"
    def __init__(self, parent=None):
        super().__init__("Android Analysis", "Kernel crash & bugreport analysis", parent)
        self.add_header_action(QPushButton("📂  Open kernel.log / bugreport"))
        self._content_layout.addWidget(_drop_zone("🤖", "Drop Android kernel logs or bugreport ZIPs here"))
        self._content_layout.addStretch()


class BatteryHealthPage(BasePage):
    """Stub — replaced by BatteryHealthPageFull when battery_health_page.py is present."""
    page_id = "battery_health"
    def __init__(self, parent=None):
        super().__init__("Battery Health", "Android battery analysis", parent)
        grid = QGridLayout()
        grid.setSpacing(12)
        grid.addWidget(_make_card("Charge Cycles", "—", "🔄", "#FFD700"), 0, 0)
        grid.addWidget(_make_card("Capacity",      "—", "🔋", "#50FA7B"), 0, 1)
        grid.addWidget(_make_card("Health Score",  "—", "❤️",  "#FF5555"), 0, 2)
        self._content_layout.addLayout(grid)
        self.add_placeholder(
            "🔋",
            "battery_health_page.py not found.\n"
            "Place it alongside main.py and restart PanicLab."
        )


class ReportsPage(BasePage):
    page_id = "reports"
    def __init__(self, parent=None):
        super().__init__("Reports", "Generated repair recommendations", parent)
        self.add_header_action(QPushButton("⬇️  Export"))
        self.add_placeholder("📋", "No reports generated yet.\nAnalyse a log to generate a repair report.")


class SettingsPage(BasePage):
    page_id = "settings"
    def __init__(self, parent=None):
        super().__init__("Settings", "Application preferences", parent)
        cfg = get_config()
        sections = [
            ("🎨  Appearance", [("Theme", cfg.ui.theme.capitalize())]),
            ("🔬  Analysis",   [("Min. confidence", f"{cfg.analysis.min_confidence}%"),
                                ("Context lines",    str(cfg.analysis.context_lines))]),
            ("📋  Reports",    [("Default format", cfg.report.output_format.upper()),
                                ("Output directory", cfg.report.default_output_dir or "Ask each time")]),
            ("🔋  Battery",    [("Battery analysis", "Enabled" if cfg.analysis.enable_battery_analysis else "Disabled"),
                                ("Module available",  "Yes" if _BATTERY_HEALTH_AVAILABLE else "No — add battery_health_page.py")]),
        ]
        for sec_title, rows in sections:
            frame = QFrame()
            frame.setProperty("role", "card")
            frame.setStyleSheet(_CARD_QSS)
            lay = QVBoxLayout(frame)
            lay.setContentsMargins(14, 12, 14, 12)
            lay.setSpacing(8)
            lay.addWidget(QLabel(sec_title, styleSheet="font-size:12px;font-weight:600;color:#CDD6F4;"))
            for key, val in rows:
                row = QHBoxLayout()
                row.addWidget(QLabel(key, styleSheet="color:#A6ADC8;font-size:11px;"))
                row.addStretch()
                row.addWidget(QLabel(val, styleSheet="color:#6C7086;font-size:11px;"))
                lay.addLayout(row)
            self._content_layout.addWidget(frame)
        self._content_layout.addStretch()


ALL_PAGES: list[type[BasePage]] = [
    DashboardPage,
    DevicesPage,
    AppleAnalysisPage,
    AndroidAnalysisPage,
    BatteryHealthPage,   # replaced at runtime below if Full variant is available
    ReportsPage,
    SettingsPage,
]

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════

_ACCEPTED_EXT = {".ips", ".panic", ".txt", ".log", ".zip", ".gz"}

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._cfg = get_config()
        self._pages: dict[str, BasePage] = {}
        self._current_page_id = ""

        # Device manager (requires device_manager.py alongside main.py)
        if _DEVICE_MANAGER_AVAILABLE:
            self._device_manager: "DeviceManager | None" = DeviceManager(
                poll_interval_ms=2000, parent=self
            )
        else:
            self._device_manager = None

        self._setup()
        self._build_ui()
        self._build_menus()
        self._restore_geometry()
        self._navigate_to(NAV_ITEMS[0].page_id)

        if self._device_manager:
            self._device_manager.start()

    def _setup(self) -> None:
        self.setWindowTitle("PanicLab")
        self.setMinimumSize(QSize(900, 600))
        self.resize(1200, 760)
        self.setStyleSheet("QMainWindow,QWidget#CW{background:#1E1E2E;}")
        self.setAcceptDrops(True)

    def _build_ui(self) -> None:
        cw = QWidget()
        cw.setObjectName("CW")
        self.setCentralWidget(cw)
        lay = QHBoxLayout(cw)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self._sidebar = Sidebar()
        self._sidebar.page_requested.connect(self._navigate_to)
        lay.addWidget(self._sidebar)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet("QStackedWidget{background:#1E1E2E;}")
        lay.addWidget(self._stack, stretch=1)

        for cls in ALL_PAGES:
            page = self._instantiate_page(cls)
            # Connect status_message only if the page actually has the signal
            # (BatteryHealthPageFull inherits from QWidget, not BasePage, so check first)
            if hasattr(page, "status_message"):
                page.status_message.connect(
                    lambda t, ms, bar=None: self._status_bar.show_message(t, ms)
                )
            self._pages[page.page_id] = page
            self._stack.addWidget(page)

        self._status_bar = AppStatusBar()
        self.setStatusBar(self._status_bar)

    def _instantiate_page(self, cls: type[BasePage]) -> QWidget:
        """
        Resolve each page class to its Full variant when available,
        passing the device_manager where accepted.
        """
        pid = cls.page_id

        # Devices page
        if pid == "devices" and _DEVICE_MANAGER_AVAILABLE and self._device_manager is not None:
            return DevicesPageFull(self._device_manager)

        # Apple analysis page
        if pid == "apple_analysis" and _APPLE_ANALYZER_AVAILABLE and AppleAnalysisPageFull is not None:
            return AppleAnalysisPageFull(device_manager=self._device_manager)

        # Android analysis page
        if pid == "android_analysis" and _ANDROID_ANALYZER_AVAILABLE and AndroidAnalysisPageFull is not None:
            return AndroidAnalysisPageFull(device_manager=self._device_manager)

        # Battery health page — Full variant with live ADB + file parsing
        if pid == "battery_health" and _BATTERY_HEALTH_AVAILABLE and BatteryHealthPageFull is not None:
            return BatteryHealthPageFull(device_manager=self._device_manager)

        # Fallback: instantiate the stub with no args
        return cls()

    def _build_menus(self) -> None:
        mb = self.menuBar()
        mb.setStyleSheet(
            "QMenuBar{background:#181825;color:#CDD6F4;font-size:12px;border-bottom:1px solid #313244;}"
            "QMenuBar::item:selected{background:#313244;border-radius:4px;}"
            "QMenu{background:#181825;color:#CDD6F4;border:1px solid #313244;}"
            "QMenu::item:selected{background:#313244;}"
            "QMenu::separator{height:1px;background:#313244;margin:4px 0;}"
        )

        fm = mb.addMenu("&File")
        oa = QAction("&Open Log File…", self)
        oa.setShortcut(QKeySequence.StandardKey.Open)
        oa.triggered.connect(self._open_dialog)
        fm.addAction(oa)
        fm.addSeparator()
        qa = QAction("&Quit", self)
        qa.setShortcut(QKeySequence.StandardKey.Quit)
        qa.triggered.connect(self.close)
        fm.addAction(qa)

        vm = mb.addMenu("&View")
        for i, item in enumerate(NAV_ITEMS, 1):
            act = QAction(f"{item.icon}  {item.label}", self)
            act.setShortcut(QKeySequence(str(i)))
            pid = item.page_id
            act.triggered.connect(lambda _, p=pid: self._navigate_to(p))
            vm.addAction(act)

        hm = mb.addMenu("&Help")
        ab = QAction("About PanicLab", self)
        ab.triggered.connect(self._about)
        hm.addAction(ab)

    def _navigate_to(self, page_id: str) -> None:
        if page_id not in self._pages:
            return
        if self._current_page_id and self._current_page_id in self._pages:
            self._pages[self._current_page_id].on_deactivated()
        page = self._pages[page_id]
        self._stack.setCurrentWidget(page)
        self._sidebar.set_active_page(page_id)
        self._current_page_id = page_id
        page.on_activated()
        title = getattr(page, "_title", page_id)
        self._status_bar.show_message(f"Navigated to {title}", 2000)

    def _open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "Log files (*.ips *.panic *.txt *.log *.zip *.gz);;All files (*)"
        )
        if path:
            self.open_file(Path(path))

    def open_file(self, path: Path) -> None:
        if not path.exists():
            self._status_bar.show_message(f"File not found: {path.name}", 5000)
            return
        self._cfg.add_recent_file(str(path))
        self._status_bar.set_context(path.name)
        self._status_bar.show_message(f"Loaded {path.name}", 3000)

        ext = path.suffix.lower()
        if ext in {".ips", ".panic"}:
            target = "apple_analysis"
        elif ext in {".zip", ".txt", ".log", ".gz"}:
            # Peek inside to decide: battery log or crash log
            target = self._route_file(path)
        else:
            target = "android_analysis"

        self._navigate_to(target)

        # Forward the file to the active page if it supports it
        page = self._pages.get(target)
        if page and hasattr(page, "_load_file"):
            page._load_file(path)  # type: ignore[attr-defined]

    def _route_file(self, path: Path) -> str:
        """
        Quickly decide whether a file is a battery log or a crash log
        by scanning the first 8 KB for distinguishing keywords.
        """
        try:
            if path.suffix.lower() == ".zip":
                import zipfile
                with zipfile.ZipFile(path, "r") as zf:
                    names = " ".join(zf.namelist())
                    sample = names[:4000]
            else:
                sample = path.read_text(errors="replace")[:8000]

            battery_hits = len(re.findall(
                r"(dumpsys battery|charge_full|battery_health|cycle_count"
                r"|charge cycle|batt_cap|batterystats)", sample, re.I
            ))
            crash_hits = len(re.findall(
                r"(tombstone|ramoops|kernel panic|Oops:|BUG:|ufshcd|last_kmsg"
                r"|signal \d+ \(SIG|backtrace:)", sample, re.I
            ))
            if battery_hits > crash_hits:
                return "battery_health"
        except Exception:
            pass
        return "android_analysis"

    # ── Drag-and-drop ─────────────────────────────────────────────────────

    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        if e.mimeData().hasUrls() and any(
            Path(u.toLocalFile()).suffix.lower() in _ACCEPTED_EXT
            for u in e.mimeData().urls() if u.isLocalFile()
        ):
            e.acceptProposedAction()
            self._status_bar.set_drop_active(True)
        else:
            e.ignore()

    def dragLeaveEvent(self, e: QDragLeaveEvent) -> None:
        self._status_bar.set_drop_active(False)
        super().dragLeaveEvent(e)

    def dropEvent(self, e: QDropEvent) -> None:
        self._status_bar.set_drop_active(False)
        paths = [
            Path(u.toLocalFile())
            for u in e.mimeData().urls()
            if u.isLocalFile()
            and Path(u.toLocalFile()).suffix.lower() in _ACCEPTED_EXT
        ]
        if paths:
            e.acceptProposedAction()
            self.open_file(paths[0])
            for p in paths[1:]:
                QTimer.singleShot(200, lambda x=p: self.open_file(x))
        else:
            e.ignore()

    # ── Geometry / lifecycle ──────────────────────────────────────────────

    def _restore_geometry(self) -> None:
        geo = self._cfg.ui.window_geometry
        if geo:
            try:
                x, y, w, h = (int(v) for v in geo.split(","))
                self.setGeometry(x, y, w, h)
            except ValueError:
                pass

    def closeEvent(self, e) -> None:
        if self._device_manager:
            self._device_manager.stop()
        g = self.geometry()
        self._cfg.ui.window_geometry = f"{g.x()},{g.y()},{g.width()},{g.height()}"
        self._cfg.save()
        super().closeEvent(e)

    def _about(self) -> None:
        lines = [
            f"<b>PanicLab</b> v{__version__}",
            "iPhone panic log &amp; Android kernel crash analyzer.",
            "",
            f"<b>Modules loaded:</b>",
            f"  DeviceManager : {'✓' if _DEVICE_MANAGER_AVAILABLE else '✗'}",
            f"  Android analyzer : {'✓' if _ANDROID_ANALYZER_AVAILABLE else '✗'}",
            f"  Apple analyzer : {'✓' if _APPLE_ANALYZER_AVAILABLE else '✗'}",
            f"  Battery health : {'✓' if _BATTERY_HEALTH_AVAILABLE else '✗'}",
        ]
        msg = QMessageBox(self)
        msg.setWindowTitle("About PanicLab")
        msg.setText("<br>".join(lines))
        msg.setStyleSheet(
            "QMessageBox{background:#181825;color:#CDD6F4;}"
            "QPushButton{background:#313244;color:#CDD6F4;border-radius:6px;padding:6px 16px;}"
        )
        msg.exec()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def _setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)-8s  %(name)s — %(message)s"))
    fh = RotatingFileHandler(
        LOG_DIR / "paniclab.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"))
    root.addHandler(ch)
    root.addHandler(fh)
    logging.getLogger("PyQt6").setLevel(logging.WARNING)


def main() -> None:
    _setup_logging()
    log = logging.getLogger(__name__)
    log.info("PanicLab %s starting", __version__)
    log.info(
        "Modules — DeviceManager:%s  Android:%s  Apple:%s  Battery:%s",
        _DEVICE_MANAGER_AVAILABLE,
        _ANDROID_ANALYZER_AVAILABLE,
        _APPLE_ANALYZER_AVAILABLE,
        _BATTERY_HEALTH_AVAILABLE,
    )

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("PanicLab")
    app.setApplicationVersion(__version__)

    cfg = get_config()
    apply_theme(app, cfg.ui.theme)

    window = MainWindow()
    if len(sys.argv) > 1:
        p = Path(sys.argv[1])
        if p.exists():
            window.open_file(p)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()