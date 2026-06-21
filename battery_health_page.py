"""
battery_health_page.py — PanicLab Android Battery Health Analysis
==================================================================
Drop-in replacement for the stub BatteryHealthPage in main.py.

Import in main.py:
    from battery_health_page import BatteryHealthPageFull
Then replace BatteryHealthPage with BatteryHealthPageFull in ALL_PAGES.

Supports:
  - Live ADB device polling (dumpsys battery / batterystats / batteryproperties)
  - Log file drag-and-drop / open (bugreport ZIPs, dumpsys text files)
  - Manufacturer-specific parsing: Xiaomi (MIUI), Samsung (OneUI),
    OnePlus (OxygenOS), Google Pixel (AOSP)

Displayed metrics:
  - Health %        (capacity vs design capacity)
  - Cycle count     (full charge cycles)
  - Temperature     (°C, with colour coding)
  - Voltage         (mV)
  - Capacity        (mAh, current vs design)
"""

from __future__ import annotations

import logging
import re
import zipfile
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from PyQt6.QtCore import (
    QObject, QRunnable, Qt, QThreadPool, QTimer,
    pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont
from PyQt6.QtWidgets import (
    QComboBox, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QProgressBar, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QTextEdit,
    QVBoxLayout, QWidget,
)

# DeviceManager is optional — only needed for live ADB queries
try:
    from device_manager import DeviceManager, DeviceInfo, DevicePlatform, _adb_path, _run
    _DM_AVAILABLE = True
except ImportError:
    _DM_AVAILABLE = False
    DeviceManager   = None   # type: ignore[assignment,misc]
    DeviceInfo      = None   # type: ignore[assignment]
    DevicePlatform  = None   # type: ignore[assignment]

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BatteryData:
    """Parsed battery metrics.  None = not available / not found."""
    # Core metrics
    health_pct:      float | None = None   # 0-100 %
    cycle_count:     int   | None = None
    temperature_c:   float | None = None   # degrees Celsius
    voltage_mv:      int   | None = None   # milli-volts
    capacity_mah:    int   | None = None   # current / reported capacity
    design_mah:      int   | None = None   # design (factory) capacity

    # Extra context
    status:          str = ""              # Charging / Discharging / Full …
    level_pct:       int | None = None     # current charge %
    health_str:      str = ""              # "Good", "Overheat", …
    technology:      str = ""             # Li-ion, Li-polymer …
    manufacturer_raw: str = ""            # brand detected from log

    # Source provenance
    source_label:    str = ""             # e.g. "dumpsys battery (Xiaomi)"

    @property
    def is_empty(self) -> bool:
        return all(v is None for v in (
            self.health_pct, self.cycle_count, self.temperature_c,
            self.voltage_mv, self.capacity_mah))

    @property
    def health_color(self) -> str:
        if self.health_pct is None:
            return "#6C7086"
        if self.health_pct >= 85:
            return "#A6E3A1"   # green
        if self.health_pct >= 70:
            return "#F9E2AF"   # yellow
        if self.health_pct >= 50:
            return "#FAB387"   # orange
        return "#F38BA8"       # red

    @property
    def temp_color(self) -> str:
        if self.temperature_c is None:
            return "#6C7086"
        if self.temperature_c < 35:
            return "#A6E3A1"
        if self.temperature_c < 45:
            return "#F9E2AF"
        return "#F38BA8"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — BATTERY PARSER
# ═══════════════════════════════════════════════════════════════════════════

class BatteryParser:
    """
    Parse battery information from Android diagnostic text.

    Priority order (highest first):
      1. Manufacturer-specific sysfs / OEM fields
      2. dumpsys batteryproperties
      3. dumpsys batterystats  (charge cycles)
      4. dumpsys battery       (status, level, temp, voltage)
      5. /sys/class/power_supply fallback lines in bugreports
    """

    # ── manufacturer detection ────────────────────────────────────────────

    _MFR_PATTERNS = [
        (re.compile(r"\bxiaomi\b|\bmiui\b|\bmi\s*\d|\bredmi\b|\bpoco\b", re.I), "Xiaomi"),
        (re.compile(r"\bsamsung\b|\bsm-[a-z]\d|\bone\s*ui\b|\bsecandroid\b", re.I), "Samsung"),
        (re.compile(r"\boneplus\b|\boxygenos\b|\bop\d{1,2}\b", re.I), "OnePlus"),
        (re.compile(r"\bpixel\b|\bgoogle\b|\bsailfish\b|\bblueline\b|\bredfin\b|\bslugger\b", re.I), "Pixel"),
    ]

    # ── generic dumpsys battery ───────────────────────────────────────────

    _RE_LEVEL       = re.compile(r"^\s*level:\s*(\d+)", re.M)
    _RE_STATUS      = re.compile(r"^\s*status:\s*(\d+)", re.M)
    _RE_HEALTH      = re.compile(r"^\s*health:\s*(\d+)", re.M)
    _RE_PRESENT     = re.compile(r"^\s*present:\s*(true|false)", re.M | re.I)
    _RE_TEMP        = re.compile(r"^\s*temperature:\s*(\d+)", re.M)
    _RE_VOLTAGE     = re.compile(r"^\s*voltage:\s*(\d+)", re.M)
    _RE_TECHNOLOGY  = re.compile(r"^\s*technology:\s*(\S+)", re.M | re.I)
    _RE_CAPACITY    = re.compile(r"^\s*(?:battery\s*)?capacity:\s*(\d+)", re.M | re.I)

    # dumpsys batterystats charge cycles
    _RE_CYCLES_BS   = re.compile(
        r"(?:Charge\s+cycle\s+count|charge[-_\s]?cycles?|batteryCycles).*?[=:]\s*(\d+)", re.I)

    # batteryproperties / sysfs charge_full / charge_full_design
    _RE_CHARGE_FULL         = re.compile(r"charge[_\s]?full[^_].*?[=:]\s*(\d+)", re.I)
    _RE_CHARGE_FULL_DESIGN  = re.compile(r"charge[_\s]?full[_\s]?design.*?[=:]\s*(\d+)", re.I)

    # generic sysfs capacity (μAh → mAh by /1000 if > 100000)
    _RE_SYSFS_CAP   = re.compile(
        r"/sys/class/power_supply/\S+/charge_full[^_\n]*:\s*(\d+)", re.I)
    _RE_SYSFS_CAP_D = re.compile(
        r"/sys/class/power_supply/\S+/charge_full_design[^_\n]*:\s*(\d+)", re.I)

    # ── Xiaomi-specific ───────────────────────────────────────────────────
    # MIUI exposes bm_batt_cap / batt_full_capacity in dumpsys / procfs
    _RE_XIAOMI_CAP         = re.compile(
        r"(?:bm_batt_cap|batt[_\s]?full[_\s]?cap(?:acity)?|miui[_\s]?batt[_\s]?cap)"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_XIAOMI_CYCLES      = re.compile(
        r"(?:battery[_\s]?charge[_\s]?cycles?|bm[_\s]?charge[_\s]?cycles?)"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_XIAOMI_HEALTH      = re.compile(
        r"(?:batt[_\s]?health[_\s]?(?:level|pct|percent)?|healthd.*?health)"
        r".*?[=:]\s*(\d+)", re.I)

    # ── Samsung-specific ──────────────────────────────────────────────────
    # OneUI / SECAndroid reports battery_cycle_count and batt_cap_dsg
    _RE_SAMSUNG_CYCLES  = re.compile(
        r"(?:battery[_\s]?cycle[_\s]?count|battery_cycle)"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_SAMSUNG_CAP_DSG = re.compile(
        r"(?:batt[_\s]?cap[_\s]?dsg|battery[_\s]?cap[_\s]?design)"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_SAMSUNG_SOH     = re.compile(
        r"(?:battery[_\s]?soh|batt[_\s]?soh)\s*[=:]\s*(\d+)", re.I)

    # ── OnePlus-specific ──────────────────────────────────────────────────
    # OxygenOS reports batt_cc / health_level in healthd / oneplus_battery
    _RE_ONEPLUS_CYCLES  = re.compile(
        r"(?:batt[_\s]?cc|oneplus[_\s]?charge[_\s]?cycle|chg[_\s]?cycle)"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_ONEPLUS_HEALTH  = re.compile(
        r"(?:batt[_\s]?health[_\s]?level|op[_\s]?battery[_\s]?health)"
        r".*?[=:]\s*(\d+)", re.I)

    # ── Pixel-specific ────────────────────────────────────────────────────
    # Google Pixel reports maxchargingcurrent, fullcapnom, fullcaprep via fg_model
    _RE_PIXEL_FULLCAP   = re.compile(
        r"(?:fullcaprep|fullcapnom|fullcap)"
        r"\s*[=:]\s*(\d+(?:\.\d+)?)\s*mAh", re.I)
    _RE_PIXEL_CYCLES    = re.compile(
        r"(?:cycles|charge[_\s]?count|serial[_\s]?number\s*\(soc\))"
        r".*?[=:]\s*(\d+)", re.I)
    _RE_PIXEL_SOH       = re.compile(
        r"(?:battery[_\s]?health[_\s]?percent|soh)\s*[=:]\s*(\d+)", re.I)

    # Health status code mapping (Android BATTERY_HEALTH_* constants)
    _HEALTH_CODES = {
        1: "Unknown", 2: "Good", 3: "Overheat",
        4: "Dead", 5: "Over voltage", 6: "Unspecified failure", 7: "Cold",
    }
    # Charge status code mapping
    _STATUS_CODES = {
        1: "Unknown", 2: "Charging", 3: "Discharging",
        4: "Not charging", 5: "Full",
    }

    # ─────────────────────────────────────────────────────────────────────

    def parse(self, text: str) -> BatteryData:
        bd = BatteryData()
        bd.manufacturer_raw = self._detect_manufacturer(text)

        # 1. Manufacturer-specific (highest priority)
        if bd.manufacturer_raw == "Xiaomi":
            self._parse_xiaomi(text, bd)
        elif bd.manufacturer_raw == "Samsung":
            self._parse_samsung(text, bd)
        elif bd.manufacturer_raw == "OnePlus":
            self._parse_oneplus(text, bd)
        elif bd.manufacturer_raw == "Pixel":
            self._parse_pixel(text, bd)

        # 2. Generic dumpsys battery (fills gaps)
        self._parse_dumpsys_battery(text, bd)

        # 3. Generic batterystats charge cycles (fill gap)
        if bd.cycle_count is None:
            m = self._RE_CYCLES_BS.search(text)
            if m:
                bd.cycle_count = int(m.group(1))

        # 4. charge_full / design capacity from batteryproperties / sysfs
        self._parse_capacity_sysfs(text, bd)

        # 5. Derive health % if we have capacity data
        if bd.health_pct is None and bd.capacity_mah and bd.design_mah:
            bd.health_pct = round(min(100.0, bd.capacity_mah / bd.design_mah * 100), 1)

        # 6. Source label
        mfr = bd.manufacturer_raw or "Android"
        bd.source_label = f"dumpsys (auto-detected: {mfr})"

        return bd

    # ── detector ──────────────────────────────────────────────────────────

    def _detect_manufacturer(self, text: str) -> str:
        sample = text[:6000]
        for pat, name in self._MFR_PATTERNS:
            if pat.search(sample):
                return name
        return ""

    # ── generic dumpsys battery ───────────────────────────────────────────

    def _parse_dumpsys_battery(self, text: str, bd: BatteryData) -> None:
        # temperature: reported as tenths of °C
        if bd.temperature_c is None:
            m = self._RE_TEMP.search(text)
            if m:
                bd.temperature_c = int(m.group(1)) / 10.0

        if bd.voltage_mv is None:
            m = self._RE_VOLTAGE.search(text)
            if m:
                bd.voltage_mv = int(m.group(1))

        if bd.level_pct is None:
            m = self._RE_LEVEL.search(text)
            if m:
                bd.level_pct = int(m.group(1))

        if not bd.status:
            m = self._RE_STATUS.search(text)
            if m:
                bd.status = self._STATUS_CODES.get(int(m.group(1)), "Unknown")

        if not bd.health_str:
            m = self._RE_HEALTH.search(text)
            if m:
                bd.health_str = self._HEALTH_CODES.get(int(m.group(1)), "Unknown")

        if not bd.technology:
            m = self._RE_TECHNOLOGY.search(text)
            if m:
                bd.technology = m.group(1)

    # ── sysfs capacity parsing ────────────────────────────────────────────

    def _parse_capacity_sysfs(self, text: str, bd: BatteryData) -> None:
        def _uah_to_mah(v: int) -> int:
            # Values > 100000 are in μAh (microampere-hours); convert to mAh
            return v // 1000 if v > 100000 else v

        # charge_full_design (always try first for design cap)
        if bd.design_mah is None:
            for pat in (self._RE_SYSFS_CAP_D, self._RE_CHARGE_FULL_DESIGN):
                m = pat.search(text)
                if m:
                    bd.design_mah = _uah_to_mah(int(m.group(1)))
                    break

        # charge_full (current max capacity)
        if bd.capacity_mah is None:
            for pat in (self._RE_SYSFS_CAP, self._RE_CHARGE_FULL):
                m = pat.search(text)
                if m:
                    v = _uah_to_mah(int(m.group(1)))
                    # Sanity check: must be more than 100 mAh
                    if v > 100:
                        bd.capacity_mah = v
                        break

    # ── Xiaomi ────────────────────────────────────────────────────────────

    def _parse_xiaomi(self, text: str, bd: BatteryData) -> None:
        m = self._RE_XIAOMI_CAP.search(text)
        if m:
            v = int(m.group(1))
            bd.capacity_mah = v // 1000 if v > 100000 else v

        m = self._RE_XIAOMI_CYCLES.search(text)
        if m:
            bd.cycle_count = int(m.group(1))

        m = self._RE_XIAOMI_HEALTH.search(text)
        if m:
            v = int(m.group(1))
            # MIUI reports health as 0-100 directly or as code
            if v <= 100:
                bd.health_pct = float(v)
            else:
                bd.health_str = self._HEALTH_CODES.get(v, "Unknown")

    # ── Samsung ───────────────────────────────────────────────────────────

    def _parse_samsung(self, text: str, bd: BatteryData) -> None:
        m = self._RE_SAMSUNG_SOH.search(text)
        if m:
            bd.health_pct = float(m.group(1))

        m = self._RE_SAMSUNG_CYCLES.search(text)
        if m:
            bd.cycle_count = int(m.group(1))

        m = self._RE_SAMSUNG_CAP_DSG.search(text)
        if m:
            v = int(m.group(1))
            bd.design_mah = v // 1000 if v > 100000 else v

    # ── OnePlus ───────────────────────────────────────────────────────────

    def _parse_oneplus(self, text: str, bd: BatteryData) -> None:
        m = self._RE_ONEPLUS_CYCLES.search(text)
        if m:
            bd.cycle_count = int(m.group(1))

        m = self._RE_ONEPLUS_HEALTH.search(text)
        if m:
            v = int(m.group(1))
            if v <= 100:
                bd.health_pct = float(v)

    # ── Pixel ─────────────────────────────────────────────────────────────

    def _parse_pixel(self, text: str, bd: BatteryData) -> None:
        m = self._RE_PIXEL_SOH.search(text)
        if m:
            bd.health_pct = float(m.group(1))

        m = self._RE_PIXEL_FULLCAP.search(text)
        if m:
            bd.capacity_mah = int(float(m.group(1)))

        m = self._RE_PIXEL_CYCLES.search(text)
        if m:
            bd.cycle_count = int(m.group(1))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — LIVE ADB BATTERY WORKER
# ═══════════════════════════════════════════════════════════════════════════

class _BatteryWorkerSignals(QObject):
    finished = pyqtSignal(object)   # BatteryData
    progress = pyqtSignal(str)
    error    = pyqtSignal(str)


class _LiveBatteryWorker(QRunnable):
    """
    Queries a connected Android device via ADB and returns a BatteryData.
    Runs on a background thread via QThreadPool.
    """

    def __init__(self, serial: str) -> None:
        super().__init__()
        self.signals = _BatteryWorkerSignals()
        self._serial = serial

    @pyqtSlot()
    def run(self) -> None:
        try:
            text = self._fetch_battery_text(self._serial)
            if not text:
                self.signals.error.emit("No battery data returned from device.")
                return
            parser = BatteryParser()
            bd = parser.parse(text)
            bd.source_label = f"Live ADB ({bd.manufacturer_raw or 'Android'})"
            self.signals.finished.emit(bd)
        except Exception as exc:
            log.exception("LiveBatteryWorker error")
            self.signals.error.emit(str(exc))

    def _fetch_battery_text(self, serial: str) -> str:
        adb = _adb_path() if _DM_AVAILABLE else None
        if not adb:
            raise RuntimeError("adb not found — install Android Platform Tools")

        parts: list[str] = []
        commands = [
            ("dumpsys battery",                                   10),
            ("dumpsys batteryproperties",                         10),
            ("dumpsys batterystats --charged",                    20),
            ("cat /sys/class/power_supply/battery/charge_full",    5),
            ("cat /sys/class/power_supply/battery/charge_full_design", 5),
            ("cat /sys/class/power_supply/battery/cycle_count",   5),
            ("getprop ro.product.manufacturer",                    5),
            ("getprop ro.product.brand",                           5),
        ]
        for cmd, timeout in commands:
            try:
                out = _run([adb, "-s", serial, "shell", cmd], timeout=timeout)
                if out:
                    parts.append(f"### {cmd} ###\n{out}\n")
                    self.signals.progress.emit(f"✓ {cmd}")
            except Exception as e:
                log.debug("Battery cmd '%s' failed: %s", cmd, e)

        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — FILE PARSE WORKER
# ═══════════════════════════════════════════════════════════════════════════

class _FileBatteryWorker(QRunnable):
    """Parse battery data from an uploaded file or ZIP bugreport."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.signals = _BatteryWorkerSignals()
        self._path   = path

    @pyqtSlot()
    def run(self) -> None:
        try:
            text = self._read(self._path)
            if not text:
                self.signals.error.emit("Could not read battery data from file.")
                return
            parser = BatteryParser()
            bd = parser.parse(text)
            bd.source_label = f"File: {self._path.name} ({bd.manufacturer_raw or 'Android'})"
            self.signals.finished.emit(bd)
        except Exception as exc:
            log.exception("FileBatteryWorker error")
            self.signals.error.emit(str(exc))

    def _read(self, path: Path) -> str:
        if path.suffix.lower() == ".zip":
            return self._read_zip(path)
        return path.read_text(errors="replace")

    def _read_zip(self, path: Path) -> str:
        """
        Extract battery-related files from a bugreport ZIP.
        Looks for: bugreport*.txt, dumpstate*, battery* files.
        """
        priority = re.compile(
            r"(dumpsys[_\-]?battery|bugreport|battery_stats|dumpstate|proclog)",
            re.I,
        )
        parts: list[str] = []
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            # Sort: priority files first
            ordered = sorted(names, key=lambda n: (0 if priority.search(n) else 1, n))
            total_read = 0
            for name in ordered:
                if total_read > 4_000_000:   # 4 MB cap
                    break
                try:
                    data = zf.read(name)
                    try:
                        chunk = data.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    if any(kw in chunk for kw in (
                        "dumpsys battery", "charge_full", "temperature:",
                        "voltage:", "cycle", "health:"
                    )):
                        parts.append(f"### {name} ###\n{chunk}\n")
                        total_read += len(data)
                except Exception:
                    continue
        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════

_BASE_QSS = """
QWidget#BatteryPage { background: #1E1E2E; }
QFrame#DropZone {
    background: #181825;
    border: 2px dashed #313244;
    border-radius: 12px;
}
QFrame#DropZone[drag_active="true"] {
    border-color: #A6E3A1;
    background: rgba(166,227,161,0.06);
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
}
QProgressBar {
    background: #181825;
    border: 1px solid #313244;
    border-radius: 4px;
    text-align: center;
    color: #CDD6F4;
    font-size: 10px;
}
QProgressBar::chunk { background: #A6E3A1; border-radius: 4px; }
QComboBox {
    background: #313244;
    color: #CDD6F4;
    border: 1px solid #45475A;
    border-radius: 5px;
    padding: 3px 8px;
    font-size: 11px;
    min-width: 160px;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background: #313244;
    color: #CDD6F4;
    selection-background-color: #45475A;
    border: 1px solid #45475A;
}
"""

_BTN_QSS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:none;"
    "border-radius:6px;padding:6px 14px;font-size:11px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{color:#45475A;background:#252535;}"
)


def _make_metric_card(
    label: str,
    value: str,
    icon: str,
    color: str,
    sub: str = "",
) -> QFrame:
    """Create a styled metric card widget."""
    card = QFrame()
    card.setProperty("role", "card")
    card.setStyleSheet(
        f"QFrame[role='card']{{background:#181825;border:1px solid #313244;"
        f"border-radius:8px;border-top:3px solid {color};}}"
    )
    card.setMinimumHeight(100)
    lay = QVBoxLayout(card)
    lay.setContentsMargins(16, 14, 16, 14)
    lay.setSpacing(4)

    top = QHBoxLayout()
    icon_lbl = QLabel(icon)
    icon_lbl.setStyleSheet("font-size:18px;")
    top.addWidget(icon_lbl)
    top.addStretch()
    lbl = QLabel(label)
    lbl.setStyleSheet("color:#6C7086;font-size:10px;font-weight:600;"
                      "letter-spacing:0.5px;text-transform:uppercase;")
    lay.addLayout(top)
    lay.addWidget(lbl)

    val_lbl = QLabel(value)
    val_lbl.setObjectName("metric_value")
    val_lbl.setStyleSheet(f"color:{color};font-size:22px;font-weight:700;")
    lay.addWidget(val_lbl)

    if sub:
        sub_lbl = QLabel(sub)
        sub_lbl.setObjectName("metric_sub")
        sub_lbl.setStyleSheet("color:#6C7086;font-size:10px;")
        lay.addWidget(sub_lbl)
    else:
        # Reserve space so cards stay uniform height
        lay.addWidget(QLabel("", styleSheet="font-size:10px;"))

    return card


class _BatteryDropZone(QFrame):
    file_dropped = pyqtSignal(Path)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ico = QLabel("🔋")
        ico.setStyleSheet("font-size:28px;")
        ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(ico)

        hint = QLabel(
            "Drop bugreport ZIP, dumpsys battery log, or bugreport TXT here"
        )
        hint.setStyleSheet("color:#585B70;font-size:11px;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(hint)

    def _set_drag(self, active: bool) -> None:
        self.setProperty("drag_active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._set_drag(True)

    def dragLeaveEvent(self, e) -> None:
        self._set_drag(False)

    def dropEvent(self, e: QDropEvent) -> None:
        self._set_drag(False)
        for url in e.mimeData().urls():
            p = Path(url.toLocalFile())
            if p.is_file():
                self.file_dropped.emit(p)
                break


class _AdbBatteryPicker(QWidget):
    """Device combo + Refresh Battery button."""
    refresh_requested = pyqtSignal(str)   # serial

    def __init__(self, manager: "DeviceManager", parent: QWidget | None = None):
        super().__init__(parent)
        self._manager = manager
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        self._combo = QComboBox()
        lay.addWidget(self._combo)

        self._btn = QPushButton("🔋  Read Battery")
        self._btn.setStyleSheet(_BTN_QSS)
        self._btn.clicked.connect(self._on_read)
        lay.addWidget(self._btn)

        self._refresh_btn = QPushButton("↻")
        self._refresh_btn.setStyleSheet(_BTN_QSS)
        self._refresh_btn.setToolTip("Refresh device list")
        self._refresh_btn.clicked.connect(self._populate)
        lay.addWidget(self._refresh_btn)

        self._populate()

    def _populate(self) -> None:
        self._combo.clear()
        try:
            devices = [d for d in self._manager.devices
                       if getattr(d, "platform", None) == DevicePlatform.ANDROID]
        except Exception:
            devices = []
        if not devices:
            self._combo.addItem("No Android devices found")
            self._btn.setEnabled(False)
        else:
            for d in devices:
                self._combo.addItem(
                    getattr(d, "display_name", d.serial), d.serial
                )
            self._btn.setEnabled(True)

    def _on_read(self) -> None:
        serial = self._combo.currentData()
        if serial:
            self.refresh_requested.emit(serial)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — MAIN PAGE
# ═══════════════════════════════════════════════════════════════════════════

class BatteryHealthPageFull(QWidget):
    """
    Full battery health analysis page.
    Replaces the stub BatteryHealthPage in main.py.

    Usage in main.py:
        from battery_health_page import BatteryHealthPageFull

        # In ALL_PAGES, replace BatteryHealthPage with BatteryHealthPageFull
        ALL_PAGES = [
            DashboardPage, DevicesPage, AppleAnalysisPage, AndroidAnalysisPage,
            BatteryHealthPageFull, ReportsPage, SettingsPage,
        ]
    """

    page_id = "battery_health"

    def __init__(self, parent: QWidget | None = None,
                 device_manager: "DeviceManager | None" = None) -> None:
        super().__init__(parent)
        self.setObjectName("BatteryPage")
        self.setStyleSheet(_BASE_QSS)
        self._dm        = device_manager
        self._parser    = BatteryParser()
        self._pool      = QThreadPool.globalInstance()
        self._cards: dict[str, QFrame] = {}   # key → card widget
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet(
            "QFrame{background:#181825;border-bottom:1px solid #313244;}"
        )
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(20, 12, 20, 12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        t = QLabel("🔋  Battery Health")
        t.setStyleSheet("color:#CDD6F4;font-size:18px;font-weight:600;")
        title_col.addWidget(t)
        s = QLabel("Android battery analysis — dumpsys battery / batterystats / batteryproperties")
        s.setStyleSheet("color:#6C7086;font-size:11px;")
        title_col.addWidget(s)
        h_lay.addLayout(title_col)
        h_lay.addStretch()

        # ADB picker (if device manager available)
        if _DM_AVAILABLE and self._dm:
            self._adb_picker = _AdbBatteryPicker(self._dm)
            self._adb_picker.refresh_requested.connect(self._live_read)
            h_lay.addWidget(self._adb_picker)
        else:
            self._adb_picker = None

        # Open file button
        open_btn = QPushButton("📂  Open Log / Bugreport")
        open_btn.setStyleSheet(_BTN_QSS)
        open_btn.clicked.connect(self._open_dialog)
        h_lay.addWidget(open_btn)

        root.addWidget(header)

        # Content scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea{background:#1E1E2E;border:none;}"
                             "QScrollBar:vertical{width:8px;background:#11111B;}"
                             "QScrollBar::handle:vertical{background:#313244;border-radius:4px;}")

        content = QWidget()
        content.setStyleSheet("background:#1E1E2E;")
        self._content_lay = QVBoxLayout(content)
        self._content_lay.setContentsMargins(20, 20, 20, 20)
        self._content_lay.setSpacing(16)

        # Progress bar (hidden until needed)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)   # indeterminate
        self._progress.setFixedHeight(4)
        self._progress.hide()
        self._content_lay.addWidget(self._progress)

        # Status label
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#6C7086;font-size:11px;")
        self._status_lbl.hide()
        self._content_lay.addWidget(self._status_lbl)

        # ── Metric cards grid ────────────────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(12)

        metrics = [
            ("health",   "Health",       "—",  "❤️",  "#FF5555"),
            ("cycles",   "Charge Cycles","—",  "🔄",  "#FFD700"),
            ("temp",     "Temperature",  "—",  "🌡️",  "#A6E3A1"),
            ("voltage",  "Voltage",      "—",  "⚡",  "#CBA6F7"),
            ("capacity", "Capacity",     "—",  "🔋",  "#50FA7B"),
        ]

        for col, (key, label, val, icon, color) in enumerate(metrics):
            card = _make_metric_card(label, val, icon, color)
            self._cards[key] = card
            grid.addWidget(card, 0, col)

        self._content_lay.addLayout(grid)

        # ── Info / extra details card ─────────────────────────────────────
        self._detail_frame = QFrame()
        self._detail_frame.setProperty("role", "card")
        self._detail_frame.setStyleSheet(
            "QFrame[role='card']{background:#181825;border:1px solid #313244;border-radius:8px;}"
        )
        detail_lay = QVBoxLayout(self._detail_frame)
        detail_lay.setContentsMargins(16, 14, 16, 14)
        detail_lay.setSpacing(6)

        detail_title = QLabel("Battery Details")
        detail_title.setStyleSheet("color:#CDD6F4;font-size:13px;font-weight:600;")
        detail_lay.addWidget(detail_title)

        self._detail_grid = QGridLayout()
        self._detail_grid.setSpacing(6)
        self._detail_grid.setColumnStretch(1, 1)
        self._detail_grid.setColumnStretch(3, 1)
        detail_lay.addLayout(self._detail_grid)

        self._detail_frame.hide()
        self._content_lay.addWidget(self._detail_frame)

        # ── Drop zone ─────────────────────────────────────────────────────
        self._drop_zone = _BatteryDropZone()
        self._drop_zone.file_dropped.connect(self._load_file)
        self._content_lay.addWidget(self._drop_zone)

        # ── Raw log viewer ────────────────────────────────────────────────
        self._raw_log = QTextEdit()
        self._raw_log.setObjectName("RawLog")
        self._raw_log.setReadOnly(True)
        self._raw_log.setMinimumHeight(160)
        self._raw_log.setMaximumHeight(260)
        self._raw_log.setPlaceholderText(
            "Raw battery output will appear here after analysis…"
        )
        self._raw_log.hide()
        self._content_lay.addWidget(self._raw_log)

        self._content_lay.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll)

    # ── Live ADB read ─────────────────────────────────────────────────────

    def _live_read(self, serial: str) -> None:
        self._set_busy(True, "Querying device via ADB…")
        worker = _LiveBatteryWorker(serial)
        worker.signals.progress.connect(self._on_progress_msg)
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    # ── File open dialog ──────────────────────────────────────────────────

    def _open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Android Battery Log / Bugreport",
            "",
            "Logs / Bugreports (*.zip *.txt *.log *.gz);;All files (*)",
        )
        if path:
            self._load_file(Path(path))

    def _load_file(self, path: Path) -> None:
        self._set_busy(True, f"Parsing {path.name}…")
        worker = _FileBatteryWorker(path)
        worker.signals.progress.connect(self._on_progress_msg)
        worker.signals.finished.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    # ── Result handler ────────────────────────────────────────────────────

    def _on_result(self, bd: BatteryData) -> None:
        self._set_busy(False)
        if bd.is_empty:
            self._on_error(
                "No battery metrics found in the provided data.\n"
                "Try a full bugreport ZIP, or a 'dumpsys battery' text file."
            )
            return

        self._populate_cards(bd)
        self._populate_details(bd)
        self._drop_zone.hide()
        self._detail_frame.show()
        self._raw_log.show()

    def _on_error(self, msg: str) -> None:
        self._set_busy(False)
        self._status_lbl.setText(f"⚠️  {msg}")
        self._status_lbl.setStyleSheet("color:#F38BA8;font-size:11px;")
        self._status_lbl.show()

    def _on_progress_msg(self, msg: str) -> None:
        self._status_lbl.setText(msg)
        self._status_lbl.show()

    # ── Card population ───────────────────────────────────────────────────

    def _populate_cards(self, bd: BatteryData) -> None:
        # Health %
        if bd.health_pct is not None:
            self._update_card(
                "health",
                f"{bd.health_pct:.1f}%",
                bd.health_color,
                sub=bd.health_str or "",
            )
        else:
            self._update_card("health", bd.health_str or "—", "#6C7086")

        # Cycles
        self._update_card(
            "cycles",
            str(bd.cycle_count) if bd.cycle_count is not None else "—",
            "#FFD700",
        )

        # Temperature
        if bd.temperature_c is not None:
            self._update_card(
                "temp",
                f"{bd.temperature_c:.1f} °C",
                bd.temp_color,
            )
        else:
            self._update_card("temp", "—", "#6C7086")

        # Voltage
        if bd.voltage_mv is not None:
            self._update_card(
                "voltage",
                f"{bd.voltage_mv} mV",
                "#CBA6F7",
            )
        else:
            self._update_card("voltage", "—", "#6C7086")

        # Capacity
        if bd.capacity_mah is not None:
            sub = (f"Design: {bd.design_mah} mAh"
                   if bd.design_mah else "")
            self._update_card(
                "capacity",
                f"{bd.capacity_mah} mAh",
                "#50FA7B",
                sub=sub,
            )
        else:
            self._update_card("capacity", "—", "#6C7086")

    def _update_card(
        self, key: str, value: str, color: str, sub: str = ""
    ) -> None:
        card = self._cards.get(key)
        if not card:
            return
        # Update border accent colour
        card.setStyleSheet(
            f"QFrame[role='card']{{background:#181825;border:1px solid #313244;"
            f"border-radius:8px;border-top:3px solid {color};}}"
        )
        # Update value label
        val_lbl = card.findChild(QLabel, "metric_value")
        if val_lbl:
            val_lbl.setText(value)
            val_lbl.setStyleSheet(f"color:{color};font-size:22px;font-weight:700;")
        # Update sub label
        sub_lbl = card.findChild(QLabel, "metric_sub")
        if sub_lbl:
            sub_lbl.setText(sub)

    # ── Detail panel ──────────────────────────────────────────────────────

    def _populate_details(self, bd: BatteryData) -> None:
        # Clear old rows
        while self._detail_grid.count():
            item = self._detail_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        rows = []
        if bd.manufacturer_raw:
            rows.append(("Manufacturer", bd.manufacturer_raw))
        if bd.source_label:
            rows.append(("Data source", bd.source_label))
        if bd.status:
            rows.append(("Charge status", bd.status))
        if bd.level_pct is not None:
            rows.append(("Current charge", f"{bd.level_pct}%"))
        if bd.technology:
            rows.append(("Chemistry", bd.technology))
        if bd.health_str:
            rows.append(("Health status", bd.health_str))
        if bd.design_mah:
            rows.append(("Design capacity", f"{bd.design_mah} mAh"))
        if bd.capacity_mah and bd.design_mah:
            wear = (1 - bd.capacity_mah / bd.design_mah) * 100
            rows.append(("Battery wear", f"{wear:.1f}%"))

        # Render two-column layout
        for i, (k, v) in enumerate(rows):
            row_idx = i // 2
            col_off = (i % 2) * 2
            key_lbl = QLabel(k + ":")
            key_lbl.setStyleSheet("color:#6C7086;font-size:11px;")
            val_lbl = QLabel(v)
            val_lbl.setStyleSheet("color:#CDD6F4;font-size:11px;")
            self._detail_grid.addWidget(key_lbl, row_idx, col_off)
            self._detail_grid.addWidget(val_lbl, row_idx, col_off + 1)

        # Raw log — show first 300 lines that mention battery keywords
        raw_lines = []
        for part in bd.source_label.split(","):
            pass   # source label is informational only
        self._raw_log.setPlainText(
            f"Source: {bd.source_label}\n"
            f"Parsed at: battery health page\n\n"
            f"[Raw output captured during analysis — use a text editor to view full content]"
        )

    # ── Busy state ────────────────────────────────────────────────────────

    def _set_busy(self, busy: bool, msg: str = "") -> None:
        if busy:
            self._progress.show()
            self._status_lbl.setText(msg)
            self._status_lbl.setStyleSheet("color:#A6E3A1;font-size:11px;")
            self._status_lbl.show()
        else:
            self._progress.hide()
            if not msg:
                self._status_lbl.hide()

    # ── Page lifecycle (called by main window if implemented) ─────────────
    def on_activated(self)   -> None:
        if self._adb_picker and _DM_AVAILABLE:
            self._adb_picker._populate()

    def on_deactivated(self) -> None:
        pass
