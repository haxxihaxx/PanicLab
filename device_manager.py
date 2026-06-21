"""
device_manager.py — PanicLab DeviceManager  (Windows + macOS + Linux)
======================================================================
Android : bundled adb / adb.exe  (tools/adb.exe next to this file, or PATH)
Apple   : Windows → iTunes/Apple Mobile Device driver enumerated via WMI /
          Registry; macOS/Linux → ideviceinfo CLI (libimobiledevice).
          No pyimobiledevice Python package required on any platform.

Folder layout expected on Windows:
    PanicLab/
    ├── main.py
    ├── device_manager.py
    └── tools/
        ├── adb.exe          ← bundled Android Debug Bridge
        ├── AdbWinApi.dll    ← required by adb.exe
        └── AdbWinUsbApi.dll ← required by adb.exe

On macOS/Linux put the platform adb binary in tools/adb (chmod +x) or
rely on adb being on PATH.

Apple on Windows requires iTunes (or Apple Devices) to be installed so
the "Apple Mobile Device USB Driver" is present. No extra Python deps.

Requirements: pip install PyQt6 pydantic platformdirs pyqtdarktheme
"""

from __future__ import annotations

import logging
import subprocess
import sys
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "sys.platform"  # resolved below
IS_WINDOWS = sys.platform == "win32"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — TOOL RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════

# Directory that contains this file — tools/ lives right beside it
_HERE = Path(__file__).resolve().parent
_TOOLS_DIR = _HERE / "tools"

def _tool_path(name: str) -> Path | None:
    """
    Resolve a CLI tool to an absolute Path.

    Search order:
    1. tools/<name>.exe  (Windows) or tools/<name>  (other) — bundled binary
    2. System PATH via shutil.which
    """
    import shutil

    candidates: list[Path] = []
    if IS_WINDOWS:
        candidates.append(_TOOLS_DIR / f"{name}.exe")
        candidates.append(_TOOLS_DIR / name)          # in case shipped without .exe
    else:
        candidates.append(_TOOLS_DIR / name)

    for c in candidates:
        if c.is_file():
            return c

    found = shutil.which(name)
    return Path(found) if found else None


def _adb_path() -> Path | None:
    return _tool_path("adb")


def _run(cmd: list[str | Path], timeout: int = 8) -> str | None:
    """
    Run a subprocess and return stripped stdout, or None on any failure.
    On Windows, CREATE_NO_WINDOW suppresses the console flash.
    """
    # encoding/errors are forced to utf-8/replace rather than left to
    # locale.getpreferredencoding(): on Windows that resolves to the legacy
    # ANSI codepage (cp1252, cp936, …) instead of UTF-8, so any unicode
    # byte in ideviceinfo/idevicecrashreport output (device names, glyphs,
    # .ips JSON) raised an uncaught UnicodeDecodeError and broke Apple
    # device discovery / panic pulling on Windows only.
    kwargs: dict = dict(capture_output=True, text=True, timeout=timeout,
                         encoding="utf-8", errors="replace")
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    # Encode paths as str — subprocess accepts Path but str is safest
    str_cmd = [str(c) for c in cmd]
    try:
        r = subprocess.run(str_cmd, **kwargs)
        return r.stdout.strip() if r.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as exc:
        log.debug("_run %s failed: %s", str_cmd[0], exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

class DevicePlatform(StrEnum):
    APPLE   = "apple"
    ANDROID = "android"


@dataclass
class DeviceInfo:
    serial:       str
    platform:     DevicePlatform
    model:        str             = "Unknown"
    manufacturer: str             = "Unknown"
    os_version:   str             = "Unknown"
    extra:        dict[str, str]  = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        name = f"{self.manufacturer} {self.model}".strip()
        return name if name and name != "Unknown Unknown" else self.serial

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DeviceInfo) and self.serial == other.serial

    def __hash__(self) -> int:
        return hash(self.serial)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — ANDROID (adb)
# ═══════════════════════════════════════════════════════════════════════════

def _android_list_serials() -> list[str]:
    adb = _adb_path()
    if not adb:
        return []
    out = _run([adb, "devices"])
    if not out:
        return []
    serials: list[str] = []
    for line in out.splitlines()[1:]:        # skip "List of devices attached"
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def _adb_prop(adb: Path, serial: str, prop: str) -> str:
    out = _run([adb, "-s", serial, "shell", "getprop", prop])
    return (out or "").strip() or "Unknown"


def _android_get_info(serial: str) -> DeviceInfo:
    info = DeviceInfo(serial=serial, platform=DevicePlatform.ANDROID)
    adb  = _adb_path()
    if not adb:
        return info

    info.manufacturer = _adb_prop(adb, serial, "ro.product.manufacturer").capitalize()
    info.model        = _adb_prop(adb, serial, "ro.product.model")
    info.os_version   = _adb_prop(adb, serial, "ro.build.version.release")
    info.extra = {
        "Brand":       _adb_prop(adb, serial, "ro.product.brand"),
        "Build ID":    _adb_prop(adb, serial, "ro.build.display.id"),
        "SDK":         _adb_prop(adb, serial, "ro.build.version.sdk"),
        "Fingerprint": _adb_prop(adb, serial, "ro.build.fingerprint"),
        "ADB binary":  str(adb),
    }
    return info


def _android_get_full_details(serial: str) -> dict[str, dict[str, str]]:
    """
    Fetch a rich set of Android device properties via adb and return them
    grouped by category.  Each value is a human-readable string.

    Returns an OrderedDict of  {section_title: {label: value}}  so callers
    can render them in a consistent, grouped layout.
    """
    from collections import OrderedDict

    adb = _adb_path()

    def prop(p: str) -> str:
        if not adb:
            return "adb not found"
        return _adb_prop(adb, serial, p)

    def shell(cmd: str, timeout: int = 8) -> str:
        if not adb:
            return "adb not found"
        out = _run([adb, "-s", serial, "shell", cmd], timeout=timeout)
        return (out or "").strip() or "Unknown"

    sections: OrderedDict[str, dict[str, str]] = OrderedDict()

    # ── Device identity ───────────────────────────────────────────────────
    sections["Device Identity"] = {
        "Serial number":     serial,
        "Manufacturer":      prop("ro.product.manufacturer").capitalize(),
        "Brand":             prop("ro.product.brand"),
        "Model":             prop("ro.product.model"),
        "Device codename":   prop("ro.product.device"),
        "Product name":      prop("ro.product.name"),
        "Hardware revision": prop("ro.hardware"),
        "Baseband":          prop("gsm.version.baseband"),
    }

    # ── Android / build ───────────────────────────────────────────────────
    sections["Android Build"] = {
        "Android version":       prop("ro.build.version.release"),
        "API level (SDK)":       prop("ro.build.version.sdk"),
        "Security patch":        prop("ro.build.version.security_patch"),
        "Build ID":              prop("ro.build.display.id"),
        "Build type":            prop("ro.build.type"),
        "Build tags":            prop("ro.build.tags"),
        "Incremental build":     prop("ro.build.version.incremental"),
        "Build date (UTC)":      prop("ro.build.date.utc"),
    }

    # ── ROM / image ───────────────────────────────────────────────────────
    sections["ROM & Bootchain"] = {
        "Build fingerprint":     prop("ro.build.fingerprint"),
        "Bootloader":            prop("ro.bootloader"),
        "Boot image version":    prop("ro.boot.revision"),
        "System image version":  prop("ro.system.build.version.release"),
        "Vendor image version":  prop("ro.vendor.build.version.release"),
        "ODM image version":     prop("ro.odm.build.version.release"),
        "Verified boot state":   prop("ro.boot.verifiedbootstate"),
        "Encryption state":      prop("ro.crypto.state"),
    }

    # ── Processor ─────────────────────────────────────────────────────────
    cpu_info = shell("cat /proc/cpuinfo")
    cpu_model = "Unknown"
    cpu_cores = "Unknown"
    for line in cpu_info.splitlines():
        low = line.lower()
        if cpu_model == "Unknown" and any(k in low for k in ("model name", "hardware", "processor")):
            cpu_model = line.split(":", 1)[-1].strip()
        if "processor" in low and line.strip()[0:9].lower() == "processor":
            try:
                cpu_cores = str(int(line.split(":", 1)[-1].strip()) + 1)
            except ValueError:
                pass

    sections["Processor"] = {
        "CPU model":      cpu_model,
        "CPU cores":      cpu_cores,
        "CPU ABI (1st)":  prop("ro.product.cpu.abi"),
        "CPU ABI (2nd)":  prop("ro.product.cpu.abi2"),
        "Instruction set":prop("ro.product.cpu.abilist"),
    }

    # ── Memory ────────────────────────────────────────────────────────────
    def _parse_meminfo(key: str) -> str:
        raw = shell(f"grep -i '{key}' /proc/meminfo")
        for line in raw.splitlines():
            if key.lower() in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        kb = int(parts[1])
                        return f"{kb // 1024} MB  ({kb:,} kB)"
                    except ValueError:
                        pass
        return "Unknown"

    sections["Memory"] = {
        "RAM total":     _parse_meminfo("MemTotal"),
        "RAM available": _parse_meminfo("MemAvailable"),
        "RAM free":      _parse_meminfo("MemFree"),
    }

    # ── Storage ───────────────────────────────────────────────────────────
    df_out = shell("df /data 2>/dev/null | tail -1")
    data_parts = df_out.split()
    storage_total = storage_free = "Unknown"
    if len(data_parts) >= 4:
        try:
            storage_total = f"{int(data_parts[1]) // 1024} MB"
            storage_free  = f"{int(data_parts[3]) // 1024} MB"
        except (ValueError, IndexError):
            pass

    sections["Storage (/data)"] = {
        "Total":   storage_total,
        "Free":    storage_free,
    }

    # ── Network ───────────────────────────────────────────────────────────
    sections["Network & Radio"] = {
        "WiFi MAC address":  shell("cat /sys/class/net/wlan0/address"),
        "Bluetooth address": prop("ro.boot.btmacaddr") or shell("settings get secure bluetooth_address"),
        "IMEI (slot 1)":     shell("service call iphonesubinfo 1 | awk -F\"'\" '{print $2}' | tr -d '.' | tr -d '\n'"),
        "Mobile network":    prop("gsm.operator.alpha"),
        "SIM state":         prop("gsm.sim.state"),
    }

    return sections


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — APPLE  (platform-specific, no pyimobiledevice)
# ═══════════════════════════════════════════════════════════════════════════

# ── 4a. Windows: enumerate via WMI (iTunes driver registers PnP devices) ──

def _apple_list_serials_windows() -> list[str]:
    """
    Query WMI for USB devices whose PNP device ID matches the Apple Mobile
    Device pattern.  iTunes / Apple Devices installs the AMDU driver which
    exposes each paired iPhone/iPad as a PnP node with the UDID embedded in
    the device ID string.

    Typical DeviceID:
        USB\\VID_05AC&PID_12A8&MI_00\\7&... (pairing handshake)
    After pairing the UDID appears in the LocationPaths or in a child node.

    We use a two-step approach:
      1. wmic — available on all Windows 10/11; parses instantly.
      2. Fallback: run ideviceinfo.exe -l if bundled.
    """
    serials: list[str] = []

    # ── Step 1: wmic PnP query ──────────────────────────────────────────
    # Apple vendor ID is 05AC; iPhones report specific PIDs in range 12xx.
    wmic_out = _run(
        ["wmic", "path", "Win32_PnPEntity",
         "where", "Manufacturer='Apple Inc.'",
         "get", "DeviceID,Name", "/format:csv"],
        timeout=10,
    )
    if wmic_out:
        for line in wmic_out.splitlines():
            # CSV: Node,DeviceID,Name
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            device_id = parts[1].strip()
            name      = parts[2].strip().lower()
            # Filter to mobile devices (iPhone, iPad, iPod)
            if not any(k in name for k in ("iphone", "ipad", "ipod")):
                continue
            # Try to extract UDID — matches both the legacy 40-char hex
            # format and the modern 8+16 hex format (iPhone XS / 2018+,
            # i.e. virtually every currently-supported device), with or
            # without the separating dash.
            import re
            match = re.search(
                r"(?<![0-9A-Fa-f])("
                r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}"
                r"|[0-9A-Fa-f]{24}"
                r"|[0-9A-Fa-f]{40}"
                r")(?![0-9A-Fa-f])",
                device_id,
            )
            if match:
                udid = match.group(1)
                if "-" not in udid and len(udid) == 24:
                    udid = f"{udid[:8]}-{udid[8:]}"
                serials.append(udid.upper())
            else:
                # Use the raw DeviceID as a stable unique key
                serials.append(device_id)

    # ── Step 2: ideviceinfo.exe -l (optional bundled tool) ──────────────
    ideviceinfo = _tool_path("ideviceinfo")
    if not serials and ideviceinfo:
        out = _run([ideviceinfo, "-l"])
        if out:
            for line in out.splitlines():
                s = line.strip()
                if s and s not in serials:
                    serials.append(s)

    return list(dict.fromkeys(serials))  # deduplicate, preserve order


def _apple_get_info_windows(serial: str) -> DeviceInfo:
    """
    Populate DeviceInfo on Windows without pyimobiledevice.

    Priority:
    1. ideviceinfo.exe (bundled tools/) — most complete info.
    2. WMI Win32_PnPEntity Name field  — gives model family at least.
    3. Registry HKLM lookup under iTunes backup keys.
    """
    info = DeviceInfo(serial=serial, platform=DevicePlatform.APPLE,
                      manufacturer="Apple")

    # ── Try bundled ideviceinfo.exe ─────────────────────────────────────
    ideviceinfo = _tool_path("ideviceinfo")
    if ideviceinfo:
        out = _run([ideviceinfo, "-u", serial], timeout=10)
        if out:
            kv: dict[str, str] = {}
            for line in out.splitlines():
                if ": " in line:
                    k, _, v = line.partition(": ")
                    kv[k.strip()] = v.strip()
            info.model      = kv.get("ProductType",    kv.get("DeviceName", "Unknown"))
            info.os_version = kv.get("ProductVersion", "Unknown")
            info.extra      = kv
            return info

    # ── Fallback: WMI Name field ─────────────────────────────────────────
    wmic_out = _run(
        ["wmic", "path", "Win32_PnPEntity",
         "where", f"DeviceID like '%{serial[:8]}%'",
         "get", "Name", "/format:csv"],
        timeout=8,
    )
    if wmic_out:
        for line in wmic_out.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 2:
                name = parts[-1].strip()
                if name and name.lower() not in ("name", ""):
                    info.model = name
                    break

    # ── Fallback: iTunes backup registry ────────────────────────────────
    _try_itunes_registry(serial, info)

    return info


def _try_itunes_registry(udid: str, info: DeviceInfo) -> None:
    """
    iTunes writes device metadata to HKCU\\Software\\Apple Computer, Inc.\\
    Mobile Device Support\\iPhone OS Devices\\<UDID>.
    Read ProductType and ProductVersion if available.
    """
    if not IS_WINDOWS:
        return
    try:
        import winreg  # type: ignore[import]
        base = (r"Software\Apple Computer, Inc."
                r"\Mobile Device Support\iPhone OS Devices")
        key_path = f"{base}\\{udid}"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            def _val(name: str) -> str:
                try:
                    return str(winreg.QueryValueEx(k, name)[0])
                except OSError:
                    return "Unknown"
            info.model      = _val("ProductType")
            info.os_version = _val("ProductVersion")
            info.extra["iTunes registry key"] = key_path
    except (OSError, ImportError):
        pass


# ── 4b. macOS / Linux: libimobiledevice CLI ────────────────────────────────

def _apple_list_serials_posix() -> list[str]:
    idevice_id = _tool_path("idevice_id")
    if not idevice_id:
        return []
    out = _run([idevice_id, "-l"])
    if not out:
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def _apple_get_info_posix(udid: str) -> DeviceInfo:
    info = DeviceInfo(serial=udid, platform=DevicePlatform.APPLE,
                      manufacturer="Apple")
    ideviceinfo = _tool_path("ideviceinfo")
    if not ideviceinfo:
        return info
    out = _run([ideviceinfo, "-u", udid])
    if not out:
        return info
    kv: dict[str, str] = {}
    for line in out.splitlines():
        if ": " in line:
            k, _, v = line.partition(": ")
            kv[k.strip()] = v.strip()
    info.model      = kv.get("ProductType", kv.get("DeviceName", "Unknown"))
    info.os_version = kv.get("ProductVersion", "Unknown")
    info.extra      = kv
    return info


# ── 4c. Public dispatch ────────────────────────────────────────────────────

def _apple_list_serials() -> list[str]:
    return _apple_list_serials_windows() if IS_WINDOWS else _apple_list_serials_posix()


def _apple_get_info(serial: str) -> DeviceInfo:
    return _apple_get_info_windows(serial) if IS_WINDOWS else _apple_get_info_posix(serial)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — BACKGROUND POLLER (QThread)
# ═══════════════════════════════════════════════════════════════════════════

class _DevicePoller(QThread):
    device_connected    = pyqtSignal(object)  # DeviceInfo
    device_disconnected = pyqtSignal(str)     # serial

    def __init__(self, interval_ms: int = 2000,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._interval_ms = interval_ms
        self._known: dict[str, DeviceInfo] = {}
        self._running = False

    def run(self) -> None:
        self._running = True
        while self._running:
            try:
                self._poll()
            except Exception as exc:
                log.warning("DevicePoller error: %s", exc)
            self.msleep(self._interval_ms)

    def stop(self) -> None:
        self._running = False
        self.wait(4000)

    def _poll(self) -> None:
        current: set[str] = set()

        for udid in _apple_list_serials():
            current.add(udid)
            if udid not in self._known:
                info = _apple_get_info(udid)
                self._known[udid] = info
                self.device_connected.emit(info)

        for serial in _android_list_serials():
            current.add(serial)
            if serial not in self._known:
                info = _android_get_info(serial)
                self._known[serial] = info
                self.device_connected.emit(info)

        for gone in set(self._known) - current:
            self.device_disconnected.emit(gone)
            del self._known[gone]

    @property
    def known_devices(self) -> dict[str, DeviceInfo]:
        return dict(self._known)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — PUBLIC DeviceManager
# ═══════════════════════════════════════════════════════════════════════════

class DeviceManager(QObject):
    """
    Signals
    -------
    device_connected(DeviceInfo)  — new device detected
    device_disconnected(str)      — device serial removed
    devices_changed()             — convenience; fired after either event
    """

    device_connected    = pyqtSignal(object)
    device_disconnected = pyqtSignal(str)
    devices_changed     = pyqtSignal()

    def __init__(self, poll_interval_ms: int = 2000,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._poller = _DevicePoller(poll_interval_ms, self)
        self._poller.device_connected.connect(self._on_connected)
        self._poller.device_disconnected.connect(self._on_disconnected)

    def start(self) -> None:
        if not self._poller.isRunning():
            log.info("DeviceManager: starting (platform=%s, adb=%s)",
                     sys.platform, _adb_path())
            self._poller.start()

    def stop(self) -> None:
        self._poller.stop()
        log.info("DeviceManager: stopped")

    @property
    def devices(self) -> list[DeviceInfo]:
        return list(self._poller.known_devices.values())

    def get_device(self, serial: str) -> DeviceInfo | None:
        return self._poller.known_devices.get(serial)

    def pull_crash_reports(self, serial: str, dest: str | Path) -> bool:
        """Pull crash reports from an Apple device (requires idevicecrashreport)."""
        tool = _tool_path("idevicecrashreport")
        if not tool:
            log.warning("idevicecrashreport not found")
            return False
        dest = Path(dest); dest.mkdir(parents=True, exist_ok=True)
        result = _run([tool, "-u", serial, "-e", str(dest)])
        if result is not None:
            log.info("Crash reports pulled → %s", dest)
            return True
        log.warning("idevicecrashreport failed for %s", serial)
        return False

    # ── Android ADB live log pull ─────────────────────────────────────────

    # Paths that adb shell can read without root on most Android devices
    _ANDROID_LOG_SOURCES: list[tuple[str, str]] = [
        # (adb-shell-path,  suggested-output-filename)
        ("/proc/last_kmsg",                  "last_kmsg.txt"),
        ("/sys/fs/pstore/console-ramoops-0", "ramoops.txt"),
        ("/sys/fs/pstore/console-ramoops",   "ramoops.txt"),
        ("/data/misc/logd/logcat.live",      "logcat.txt"),
    ]

    # logcat buffers to capture (kernel + system + crash)
    _LOGCAT_BUFFERS = ["-b", "kernel", "-b", "system", "-b", "crash"]

    def pull_android_crash_logs(
        self,
        serial: str,
        *,
        progress_cb: "Callable[[str], None] | None" = None,
    ) -> "tuple[str, str] | None":
        """
        Pull Android crash / kernel logs from a connected device via ADB.

        Returns ``(log_text, source_label)`` on success, or ``None`` on failure.

        Strategy
        --------
        1. Try well-known ramoops / last_kmsg paths in ``/proc`` or ``/sys/fs/pstore``.
        2. If none found, fall back to a live ``adb logcat`` dump (kernel + system +
           crash buffers, last 10 000 lines).  Logcat is always available but only
           shows the *current* boot; ramoops/last_kmsg survive across reboots.
        3. Both paths run without root — they rely on world-readable kernel interfaces
           that most unmodified Android builds expose.
        """
        adb = _adb_path()
        if not adb:
            log.error("adb not found — cannot pull Android logs")
            return None

        def _emit(msg: str) -> None:
            log.info(msg)
            if progress_cb:
                progress_cb(msg)

        _emit(f"Connecting to {serial}…")

        # ── Step 1: try static kernel crash sources ───────────────────
        for device_path, fname in self._ANDROID_LOG_SOURCES:
            _emit(f"Checking {device_path}…")
            # "adb shell ls <path>" returns the path if it exists, error otherwise
            probe = _run([adb, "-s", serial, "shell", "ls", device_path], timeout=6)
            if not probe or "No such file" in probe or "Permission denied" in probe:
                continue

            _emit(f"Pulling {device_path}…")
            content = _run(
                [adb, "-s", serial, "shell", "cat", device_path],
                timeout=30,
            )
            if content and len(content.strip()) > 100:
                _emit(f"✅  Got kernel log from {device_path} ({len(content):,} bytes)")
                return content, device_path
            log.debug("Path %s exists but returned empty/tiny content", device_path)

        # ── Step 2: try bugreport tombstones ─────────────────────────
        _emit("Checking /data/tombstones…")
        tombstone_ls = _run(
            [adb, "-s", serial, "shell", "ls", "-t", "/data/tombstones/"],
            timeout=8,
        )
        if tombstone_ls and "Permission denied" not in tombstone_ls and "No such" not in tombstone_ls:
            # Take the most-recent tombstone
            names = [n.strip() for n in tombstone_ls.splitlines() if n.strip()]
            if names:
                newest = names[0]
                _emit(f"Pulling tombstone {newest}…")
                content = _run(
                    [adb, "-s", serial, "shell", "cat", f"/data/tombstones/{newest}"],
                    timeout=30,
                )
                if content and len(content.strip()) > 100:
                    _emit(f"✅  Got tombstone {newest} ({len(content):,} bytes)")
                    return content, f"/data/tombstones/{newest}"

        # ── Step 3: live logcat dump (always available) ───────────────
        _emit("Falling back to logcat dump (last 10 000 lines)…")
        kwargs: dict = dict(capture_output=True, text=True, timeout=20,
                            encoding="utf-8", errors="replace")
        if IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        cmd = [
            str(adb), "-s", serial, "logcat",
            *self._LOGCAT_BUFFERS,
            "-d",          # dump and exit (do not stream)
            "-v", "threadtime",
            "-t", "10000", # last 10 000 lines
        ]
        try:
            r = subprocess.run(cmd, **kwargs)
            content = r.stdout.strip()
            if content and len(content) > 50:
                _emit(f"✅  Got logcat dump ({len(content):,} bytes)")
                return content, "logcat (live)"
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("logcat fallback failed: %s", exc)

        _emit("❌  No crash logs found on device")
        return None

    def _on_connected(self, info: DeviceInfo) -> None:
        log.info("Connected  %-20s  [%s]  %s %s  OS %s",
                 info.serial[:20], info.platform,
                 info.manufacturer, info.model, info.os_version)
        self.device_connected.emit(info)
        self.devices_changed.emit()

    def _on_disconnected(self, serial: str) -> None:
        log.info("Disconnected  %s", serial)
        self.device_disconnected.emit(serial)
        self.devices_changed.emit()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — TOOL STATUS  (for UI banner)
# ═══════════════════════════════════════════════════════════════════════════

def tool_status() -> dict[str, str]:
    """
    Return a dict of tool_name → status_string for display in the Devices page.
    Status is one of: 'bundled', 'system', 'missing'.
    """
    import shutil

    result: dict[str, str] = {}

    tools_to_check: list[str]
    if IS_WINDOWS:
        tools_to_check = ["adb", "ideviceinfo", "idevicecrashreport"]
    else:
        tools_to_check = ["adb", "idevice_id", "ideviceinfo", "idevicecrashreport"]

    for name in tools_to_check:
        p = _tool_path(name)
        if p is None:
            result[name] = "missing"
        elif _TOOLS_DIR in p.parents:
            result[name] = "bundled"
        else:
            result[name] = "system"

    if IS_WINDOWS:
        # wmic is always present on Windows 10/11 — used for Apple enumeration
        result["wmic (Apple detection)"] = "system"

    return result


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — DEVICES PAGE  (Qt widget)
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8a — DEVICE DETAILS DIALOG
# ═══════════════════════════════════════════════════════════════════════════

class DeviceDetailsDialog:
    """
    Opens a native QDialog displaying rich device information.

    For Android devices it fetches extended properties (security patch,
    serial, ROM fingerprint, bootloader, memory, storage …) via adb in a
    background thread so the UI never freezes.

    For Apple devices it renders whatever is already stored in info.extra
    (populated by ideviceinfo) in the same grouped layout.

    Usage:
        dlg = DeviceDetailsDialog(info, parent=self)
        dlg.open()   # non-blocking
    """

    # ── Palette (matches Catppuccin Mocha used throughout the app) ─────
    _BG       = "#1E1E2E"
    _BG_ALT   = "#181825"
    _BORDER   = "#313244"
    _TEXT     = "#CDD6F4"
    _SUBTEXT  = "#6C7086"
    _SURFACE  = "#313244"
    _OVERLAY  = "#45475A"
    _GREEN    = "#50FA7B"
    _BLUE     = "#8BE9FD"
    _MAUVE    = "#CBA6F7"
    _YELLOW   = "#F1FA8C"

    _PLATFORM_ACCENT = {
        DevicePlatform.ANDROID: "#50FA7B",
        DevicePlatform.APPLE:   "#8BE9FD",
    }

    def __init__(self, info: DeviceInfo,
                 parent: "QWidget | None" = None) -> None:
        self._info   = info
        self._parent = parent
        self._dialog: "QDialog | None" = None

    def open(self) -> None:
        """Build and show the dialog (non-blocking)."""
        from PyQt6.QtCore    import Qt, QThread, pyqtSignal, QObject
        from PyQt6.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QLabel,
            QScrollArea, QWidget, QFrame, QPushButton,
            QSizePolicy, QProgressBar,
        )

        info   = self._info
        accent = self._PLATFORM_ACCENT.get(info.platform, self._MAUVE)
        icon   = _PLATFORM_ICON.get(info.platform, "📱")

        dlg = QDialog(self._parent)
        dlg.setWindowTitle(f"Device Details — {info.display_name}")
        dlg.setMinimumSize(680, 560)
        dlg.resize(780, 640)
        dlg.setStyleSheet(f"""
            QDialog {{ background:{self._BG}; color:{self._TEXT}; }}
            QScrollArea {{ border:none; background:{self._BG}; }}
            QScrollBar:vertical {{ width:8px; background:{self._BG_ALT}; }}
            QScrollBar::handle:vertical {{
                background:{self._SURFACE}; border-radius:4px; min-height:20px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height:0; }}
        """)

        root = QVBoxLayout(dlg)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────
        header = QFrame()
        header.setFixedHeight(70)
        header.setStyleSheet(
            f"background:{self._BG_ALT};"
            f"border-bottom:1px solid {self._BORDER};"
        )
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(20, 0, 20, 0)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size:36px; color:{accent};")
        icon_lbl.setFixedWidth(52)
        h_lay.addWidget(icon_lbl)

        title_col = QVBoxLayout(); title_col.setSpacing(2)
        lbl_name = QLabel(info.display_name)
        lbl_name.setStyleSheet(
            f"font-size:17px; font-weight:700; color:{self._TEXT};"
        )
        lbl_serial = QLabel(f"Serial / UDID:  {info.serial}")
        lbl_serial.setStyleSheet(
            f"font-size:10px; color:{self._SUBTEXT};"
        )
        title_col.addWidget(lbl_name)
        title_col.addWidget(lbl_serial)
        h_lay.addLayout(title_col, stretch=1)

        platform_badge = QLabel(info.platform.capitalize())
        platform_badge.setStyleSheet(
            f"background:{self._SURFACE}; color:{accent};"
            f"font-size:11px; font-weight:600; border-radius:4px;"
            f"padding:3px 10px;"
        )
        h_lay.addWidget(platform_badge)

        root.addWidget(header)

        # ── Loading bar (shown while fetching Android details) ────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)          # indeterminate
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar {{ background:{self._BG_ALT}; border:none; }}"
            f"QProgressBar::chunk {{ background:{accent}; }}"
        )
        root.addWidget(self._progress)

        # ── Scroll area for sections ──────────────────────────────────────
        scroll_content = QWidget()
        scroll_content.setStyleSheet(f"background:{self._BG};")
        self._sections_layout = QVBoxLayout(scroll_content)
        self._sections_layout.setContentsMargins(20, 16, 20, 20)
        self._sections_layout.setSpacing(14)
        self._sections_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        root.addWidget(scroll, stretch=1)

        # ── Close button ──────────────────────────────────────────────────
        footer = QFrame()
        footer.setStyleSheet(
            f"background:{self._BG_ALT};"
            f"border-top:1px solid {self._BORDER};"
        )
        footer.setFixedHeight(50)
        f_lay = QHBoxLayout(footer)
        f_lay.setContentsMargins(20, 0, 20, 0)
        f_lay.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setFixedWidth(90)
        btn_close.setStyleSheet(
            f"QPushButton{{background:{self._SURFACE};color:{self._TEXT};"
            f"border-radius:5px;padding:6px 12px;font-size:11px;border:none;}}"
            f"QPushButton:hover{{background:{self._OVERLAY};}}"
        )
        btn_close.clicked.connect(dlg.close)
        f_lay.addWidget(btn_close)
        root.addWidget(footer)

        self._dialog = dlg

        # ── Populate data ─────────────────────────────────────────────────
        if info.platform == DevicePlatform.ANDROID:
            self._fetch_android_async(accent)
        else:
            self._render_apple(accent)

        dlg.show()

    # ── Android: background fetch ─────────────────────────────────────────

    def _fetch_android_async(self, accent: str) -> None:
        from PyQt6.QtCore import QThread, pyqtSignal, QObject

        info = self._info

        class _Fetcher(QObject):
            done = pyqtSignal(object)  # dict[str, dict[str, str]]

            def __init__(self, serial: str) -> None:
                super().__init__()
                self._serial = serial

            def run(self) -> None:
                try:
                    data = _android_get_full_details(self._serial)
                except Exception as exc:
                    log.warning("Details fetch failed: %s", exc)
                    data = {"Error": {"Detail": str(exc)}}
                self.done.emit(data)

        self._thread  = QThread()
        self._fetcher = _Fetcher(info.serial)
        self._fetcher.moveToThread(self._thread)
        self._thread.started.connect(self._fetcher.run)
        self._fetcher.done.connect(self._on_android_data)
        self._fetcher.done.connect(self._thread.quit)
        # Stop the thread cleanly if the user closes the dialog before it
        # finishes — prevents "QThread destroyed while still running".
        if self._dialog is not None:
            self._dialog.finished.connect(self._stop_thread)
        self._thread.start()

    def _stop_thread(self) -> None:
        if hasattr(self, "_thread") and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)  # give it up to 3 s to exit cleanly

    def _on_android_data(self, sections: "dict[str, dict[str, str]]") -> None:
        self._progress.hide()
        self._render_sections(sections, accent=self._PLATFORM_ACCENT[DevicePlatform.ANDROID])

    # ── Apple: render from existing info.extra ────────────────────────────

    def _render_apple(self, accent: str) -> None:
        self._progress.hide()
        # Group Apple's flat kv dict into meaningful sections
        from collections import OrderedDict

        raw = self._info.extra
        known_identity = {
            "DeviceName", "ProductType", "ProductVersion",
            "BuildVersion", "UniqueDeviceID", "SerialNumber",
        }
        known_hw = {
            "HardwareModel", "CPUArchitecture", "BoardId",
            "ChipID", "ModelNumber",
        }
        known_sw = {
            "PasswordProtected", "ProductionSOC", "TrustedHostAttached",
            "WifiVendor", "WiFiAddress", "BluetoothAddress", "EthernetAddress",
        }

        identity = {k: raw[k] for k in known_identity if k in raw}
        hardware = {k: raw[k] for k in known_hw if k in raw}
        network  = {k: raw[k] for k in known_sw if k in raw}
        rest     = {k: v for k, v in raw.items()
                    if k not in known_identity | known_hw | known_sw}

        sections: "dict[str, dict[str, str]]" = OrderedDict()
        if identity: sections["Device Identity"] = identity
        if hardware: sections["Hardware"]         = hardware
        if network:  sections["Network & Security"] = network
        if rest:     sections["Additional Info"]  = rest

        if not sections:
            sections["Info"] = {k: v for k, v in [
                ("Model",      self._info.model),
                ("OS version", self._info.os_version),
                ("Serial",     self._info.serial),
            ]}

        self._render_sections(sections, accent=accent)

    # ── Shared renderer ───────────────────────────────────────────────────

    def _render_sections(
        self,
        sections: "dict[str, dict[str, str]]",
        accent: str,
    ) -> None:
        from PyQt6.QtWidgets import QLabel, QFrame, QVBoxLayout, QGridLayout
        from PyQt6.QtCore    import Qt

        for section_title, rows in sections.items():
            # Section header
            sec_hdr = QLabel(section_title.upper())
            sec_hdr.setStyleSheet(
                f"color:{accent}; font-size:9px; font-weight:700;"
                f"letter-spacing:1.2px; padding-bottom:2px;"
            )
            self._sections_layout.addWidget(sec_hdr)

            # Card frame
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background:{self._BG_ALT}; border:1px solid {self._BORDER};"
                f"border-radius:8px; }}"
            )
            grid = QGridLayout(card)
            grid.setContentsMargins(14, 10, 14, 10)
            grid.setHorizontalSpacing(20)
            grid.setVerticalSpacing(6)
            grid.setColumnStretch(1, 1)

            for row_idx, (label, value) in enumerate(rows.items()):
                lbl_key = QLabel(label)
                lbl_key.setStyleSheet(
                    f"font-size:10px; color:{self._SUBTEXT};"
                    f"font-weight:500; background:transparent;"
                )
                lbl_key.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                lbl_key.setFixedWidth(180)

                lbl_val = QLabel(value or "—")
                lbl_val.setStyleSheet(
                    f"font-size:10px; color:{self._TEXT}; background:transparent;"
                )
                lbl_val.setWordWrap(True)
                lbl_val.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )

                # Highlight security patch date
                if "security" in label.lower() and value and value != "Unknown":
                    lbl_val.setStyleSheet(
                        f"font-size:10px; color:{self._GREEN};"
                        f"font-weight:600; background:transparent;"
                    )

                # Highlight missing / unknown
                if value in ("Unknown", "", "adb not found", None):
                    lbl_val.setStyleSheet(
                        f"font-size:10px; color:{self._OVERLAY};"
                        f"font-style:italic; background:transparent;"
                    )

                grid.addWidget(lbl_key, row_idx, 0)
                grid.addWidget(lbl_val, row_idx, 1)

                # Separator line between rows
                if row_idx < len(rows) - 1:
                    sep = QFrame()
                    sep.setFrameShape(QFrame.Shape.HLine)
                    sep.setStyleSheet(f"color:{self._BORDER}; background:{self._BORDER};")
                    sep.setFixedHeight(1)
                    grid.addWidget(sep, row_idx + 1, 0, 1, 2)

                    # Shift next actual row down by one to account for separator
                    # (we handle this by incrementing row_idx in a second pass)

            # Rebuild grid with separators properly interleaved
            # (re-do in a cleaner single pass)
            while grid.count():
                item = grid.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            items = list(rows.items())
            grid_row = 0
            for i, (label, value) in enumerate(items):
                lbl_key = QLabel(label)
                lbl_key.setStyleSheet(
                    f"font-size:10px; color:{self._SUBTEXT}; font-weight:500;"
                    f"background:transparent;"
                )
                lbl_key.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                lbl_key.setFixedWidth(180)

                lbl_val = QLabel(value or "—")
                lbl_val.setWordWrap(True)
                lbl_val.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse
                )

                val_style = f"font-size:10px; color:{self._TEXT}; background:transparent;"
                if "security" in label.lower() and value not in ("Unknown", "", None):
                    val_style = (
                        f"font-size:10px; color:{self._GREEN}; font-weight:600;"
                        f"background:transparent;"
                    )
                elif value in ("Unknown", "", "adb not found", None):
                    val_style = (
                        f"font-size:10px; color:{self._OVERLAY}; font-style:italic;"
                        f"background:transparent;"
                    )
                lbl_val.setStyleSheet(val_style)

                grid.addWidget(lbl_key, grid_row, 0)
                grid.addWidget(lbl_val, grid_row, 1)
                grid_row += 1

                if i < len(items) - 1:
                    sep = QFrame()
                    sep.setFrameShape(QFrame.Shape.HLine)
                    sep.setStyleSheet(
                        f"border:none; background:{self._BORDER}; max-height:1px;"
                    )
                    sep.setMaximumHeight(1)
                    grid.addWidget(sep, grid_row, 0, 1, 2)
                    grid_row += 1

            self._sections_layout.addWidget(card)


_CARD_QSS = """
QFrame[role="dev-card"] {
    background: #1E1E2E;
    border: 1px solid #313244;
    border-radius: 8px;
}
QFrame[role="dev-card"]:hover { border-color: #CBA6F7; }
"""

_PLATFORM_ICON  = {DevicePlatform.APPLE: "🍎", DevicePlatform.ANDROID: "🤖"}
_PLATFORM_COLOR = {DevicePlatform.APPLE: "#8BE9FD", DevicePlatform.ANDROID: "#50FA7B"}

_BTN_QSS = (
    "QPushButton{background:#313244;color:#CDD6F4;border-radius:5px;"
    "padding:4px 10px;font-size:10px;border:none;}"
    "QPushButton:hover{background:#45475A;}"
)


def _build_device_card(info: DeviceInfo,
                       on_pull_crashes: "callable | None" = None,
                       on_details: "callable | None" = None) -> QFrame:
    from PyQt6.QtCore import Qt

    color = _PLATFORM_COLOR.get(info.platform, "#CBA6F7")
    icon  = _PLATFORM_ICON.get(info.platform, "📱")

    card = QFrame()
    card.setProperty("role", "dev-card")
    card.setStyleSheet(_CARD_QSS)
    card.setFixedHeight(116)

    root = QHBoxLayout(card)
    root.setContentsMargins(14, 12, 14, 12)
    root.setSpacing(14)

    # Platform icon
    icon_lbl = QLabel(icon)
    icon_lbl.setStyleSheet(f"font-size:36px; color:{color};")
    icon_lbl.setFixedWidth(48)
    root.addWidget(icon_lbl)

    # Info column
    info_col = QVBoxLayout(); info_col.setSpacing(3)

    name_lbl = QLabel(info.display_name)
    name_lbl.setStyleSheet("font-size:14px;font-weight:600;color:#CDD6F4;")

    serial_lbl = QLabel(f"Serial / UDID:  {info.serial}")
    serial_lbl.setStyleSheet("font-size:9px;color:#6C7086;")

    # Four labelled fields in a row
    fields_row = QHBoxLayout(); fields_row.setSpacing(20)
    for label, val in [
        ("Model",        info.model),
        ("Manufacturer", info.manufacturer),
        ("OS",           info.os_version),
        ("Platform",     info.platform.capitalize()),
    ]:
        col = QVBoxLayout(); col.setSpacing(1)
        col.addWidget(QLabel(label, styleSheet="font-size:9px;color:#45475A;font-weight:500;"))
        col.addWidget(QLabel(val,   styleSheet=f"font-size:11px;color:{color};"))
        fields_row.addLayout(col)
    fields_row.addStretch()

    info_col.addWidget(name_lbl)
    info_col.addWidget(serial_lbl)
    info_col.addLayout(fields_row)
    root.addLayout(info_col, stretch=1)

    # Buttons
    btn_col = QVBoxLayout()
    btn_col.setSpacing(5)
    btn_col.setAlignment(Qt.AlignmentFlag.AlignVCenter)

    if info.platform == DevicePlatform.APPLE:
        btn_crash = QPushButton("📥  Pull Crashes")
        btn_crash.setStyleSheet(_BTN_QSS)
        if on_pull_crashes:
            btn_crash.clicked.connect(on_pull_crashes)
        btn_col.addWidget(btn_crash)

    btn_detail = QPushButton("ℹ️  Details")
    btn_detail.setStyleSheet(_BTN_QSS)
    if on_details:
        btn_detail.clicked.connect(on_details)
    btn_col.addWidget(btn_detail)

    root.addLayout(btn_col)
    return card


class DevicesPageFull(QWidget):
    """
    Full replacement for the DevicesPage stub in main.py.
    Accepts a DeviceManager and self-updates on connect/disconnect.
    """

    page_id = "devices"
    _title  = "Devices"

    from PyQt6.QtCore import pyqtSignal as _sig
    status_message = _sig(str, int)

    def __init__(self, manager: DeviceManager,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._cards: dict[str, QFrame] = {}
        self._open_detail_dialogs: list[DeviceDetailsDialog] = []
        self._build_ui()
        manager.device_connected.connect(self._on_connected)
        manager.device_disconnected.connect(self._on_disconnected)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        from PyQt6.QtCore import Qt

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QFrame(); header.setObjectName("PageHeader")
        header.setFixedHeight(56)
        header.setStyleSheet(
            "QFrame#PageHeader{background:#181825;border-bottom:1px solid #313244;}"
            "QLabel#PageTitle{color:#CDD6F4;font-size:18px;font-weight:600;}"
            "QLabel#PageSub{color:#6C7086;font-size:11px;}"
        )
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(20, 0, 16, 0); h_lay.setSpacing(8)
        txt = QVBoxLayout(); txt.setSpacing(1)
        txt.addWidget(QLabel("Devices", objectName="PageTitle"))
        txt.addWidget(QLabel("Live-connected Apple & Android devices",
                             objectName="PageSub"))
        h_lay.addLayout(txt); h_lay.addStretch()

        self._status_dot   = QLabel("⬤")
        self._status_dot.setStyleSheet("color:#50FA7B;font-size:10px;")
        self._status_label = QLabel("Scanning…")
        self._status_label.setStyleSheet("color:#6C7086;font-size:10px;")
        h_lay.addWidget(self._status_dot)
        h_lay.addWidget(self._status_label)
        root.addWidget(header)

        # Scrollable list
        content = QWidget(); content.setStyleSheet("background:#1E1E2E;")
        self._list_layout = QVBoxLayout(content)
        self._list_layout.setContentsMargins(20, 16, 20, 16)
        self._list_layout.setSpacing(10)
        self._list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        scroll.setStyleSheet(
            "QScrollArea{border:none;background:#1E1E2E;}"
            "QScrollBar:vertical{width:8px;background:#11111B;}"
            "QScrollBar::handle:vertical{background:#313244;border-radius:4px;min-height:20px;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        )
        root.addWidget(scroll, stretch=1)

        # Empty state label
        self._empty_lbl = QLabel(
            "📱\n\nNo devices connected.\n"
            "Plug in an iPhone or Android phone."
        )
        self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_lbl.setStyleSheet(
            "color:#45475A;font-size:13px;padding:48px;"
        )
        self._list_layout.addWidget(self._empty_lbl)

        # Tool status banner
        self._build_tool_banner()

    def _build_tool_banner(self) -> None:
        status = tool_status()
        missing = [t for t, s in status.items() if s == "missing"]
        bundled = [t for t, s in status.items() if s == "bundled"]

        lines: list[str] = []
        if missing:
            lines.append(f"⚠️  Missing: {', '.join(missing)}")
        if bundled:
            lines.append(f"✅  Bundled: {', '.join(bundled)}")
        if IS_WINDOWS and "wmic (Apple detection)" in status:
            lines.append("🍎  Apple detection: Windows WMI (no extra tools needed)")

        if not lines:
            return

        banner = QLabel("\n".join(lines))
        banner.setStyleSheet(
            "background:#1A1A2E;color:#CDD6F4;font-size:10px;"
            "padding:8px 14px;border-radius:6px;"
            "border:1px solid #313244;"
        )
        banner.setWordWrap(True)
        self._list_layout.addWidget(banner)

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_connected(self, info: DeviceInfo) -> None:
        self._empty_lbl.hide()

        def _pull():
            from PyQt6.QtWidgets import QFileDialog
            dest, _ = QFileDialog.getExistingDirectory(
                self, "Save crash reports to…")
            if dest:
                ok = self._manager.pull_crash_reports(info.serial, dest)
                self.status_message.emit(
                    f"Crash reports {'saved to ' + dest if ok else 'pull failed'}",
                    4000,
                )

        def _show_details():
            d = DeviceDetailsDialog(info, parent=self)
            self._open_detail_dialogs.append(d)
            d.open()
            # Remove from list when the dialog window is closed so Python
            # doesn't keep a reference (and QThread is stopped first).
            if d._dialog is not None:
                d._dialog.finished.connect(
                    lambda: self._open_detail_dialogs.remove(d)
                    if d in self._open_detail_dialogs else None
                )

        card = _build_device_card(info, on_pull_crashes=_pull,
                                  on_details=_show_details)
        self._cards[info.serial] = card
        self._list_layout.insertWidget(0, card)
        self._refresh_status()
        self.status_message.emit(f"Device connected: {info.display_name}", 3000)

    def _on_disconnected(self, serial: str) -> None:
        if card := self._cards.pop(serial, None):
            self._list_layout.removeWidget(card)
            card.deleteLater()
        if not self._cards:
            self._empty_lbl.show()
        self._refresh_status()
        self.status_message.emit(f"Device disconnected: {serial[:20]}", 3000)

    def _refresh_status(self) -> None:
        n = len(self._cards)
        self._status_label.setText(
            f"{n} device{'s' if n != 1 else ''} connected"
        )

    # BasePage contract
    def on_activated(self)   -> None: pass
    def on_deactivated(self) -> None: pass


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9 — INTEGRATION GUIDE (unchanged — see main.py patch)
# ═══════════════════════════════════════════════════════════════════════════
#
# No changes to main.py are required beyond what was already patched:
#
#   from device_manager import DeviceManager, DevicesPageFull
#
# Folder layout on Windows:
#   PanicLab/
#   ├── main.py
#   ├── device_manager.py
#   └── tools/
#       ├── adb.exe
#       ├── AdbWinApi.dll
#       ├── AdbWinUsbApi.dll
#       └── ideviceinfo.exe        ← optional, improves Apple detail
#
# Apple on Windows (no pyimobiledevice):
#   • iTunes or "Apple Devices" app must be installed (provides AMDU driver).
#   • WMI enumerates the device; Registry reads firmware version.
#   • If ideviceinfo.exe is bundled, full model/OS info is fetched instead.
#
# Apple on macOS/Linux:
#   • brew install libimobiledevice   →  idevice_id + ideviceinfo
#   • or place the binaries in tools/
#
# Android (all platforms):
#   • Place adb(.exe) in tools/ — no system install needed.
#   • USB debugging must be enabled on the device.