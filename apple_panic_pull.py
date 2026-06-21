"""
apple_panic_pull.py — PanicLab Apple Panic Log Puller
======================================================
Pulls panic logs directly from a connected iPhone/iPad using
libimobiledevice CLI tools.

Supported pull methods (tried in priority order):
  1. idevicecrashreport  — pulls all CrashReporter files (panic-full, .ips)
  2. idevicediagnostics  — forces a diagnostic log bundle (analytics panics)
  3. idevicecrashreport --base64 — base64-encoded panic blob (panic-base)
  4. AFC file access via idevicebackup2 — sysdiagnose-style pull

Handles:
  - panic-full  : plain kernel panic text from CrashReporter
  - panic-base  : binary/base64 blobs from /var/mobile/Library/Logs/CrashReporter
  - analytics   : .ips JSON files from /var/mobile/Library/Logs/DiagnosticMessages
  - sysdiagnose : panic files inside sysdiagnose .tar.gz bundles

Requirements:
  - libimobiledevice installed (brew install libimobiledevice on macOS,
    apt install libimobiledevice-utils on Linux, or bundled in tools/)
  - Device trusted / paired (idevicepair pair)

Tool search order:
  1. tools/<name>[.exe]  — bundled next to this file
  2. System PATH
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)

IS_WIN  = sys.platform == "win32"
IS_MAC  = sys.platform == "darwin"
IS_LIN  = sys.platform.startswith("linux")

_HERE       = Path(__file__).resolve().parent
_TOOLS_DIR  = _HERE / "tools"

# Panic-relevant file extensions/patterns to collect after pull
_PANIC_EXTENSIONS = {".ips", ".panic", ".txt", ".log", ""}
_PANIC_KEYWORDS   = ("panic", "crash", "DiagnosticMessages", "ips", "tombstone")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — TOOL RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════

def _find_tool(name: str) -> Path | None:
    """Locate a libimobiledevice CLI tool: bundled tools/ dir first, then PATH."""
    candidates: list[Path] = []
    if IS_WIN:
        candidates += [_TOOLS_DIR / f"{name}.exe", _TOOLS_DIR / name]
    else:
        candidates.append(_TOOLS_DIR / name)

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c

    found = shutil.which(name)
    return Path(found) if found else None


def _run(cmd: list[str | Path], timeout: int = 30,
         capture: bool = True) -> tuple[int, str, str]:
    """
    Run a subprocess. Returns (returncode, stdout, stderr).
    Always safe — never raises on process errors.
    """
    kw: dict = {"timeout": timeout}
    if capture:
        kw["capture_output"] = True
        # IMPORTANT: explicitly force UTF-8 decoding of stdout/stderr.
        # Without this, Python falls back to locale.getpreferredencoding(),
        # which on POSIX is UTF-8 (so this "just works" on macOS/Linux) but
        # on Windows is the legacy ANSI codepage (e.g. cp1252/cp936). The
        # libimobiledevice CLI tools (idevicecrashreport, ideviceinfo, …)
        # emit UTF-8 text — device names, unicode glyphs, .ips JSON content —
        # which is frequently *not valid* in those codepages. That raised an
        # uncaught UnicodeDecodeError (a ValueError subtype, NOT caught by
        # the except clause below) and silently broke every panic-log pull
        # on Windows, even though tool discovery succeeded.
        kw["text"] = True
        kw["encoding"] = "utf-8"
        kw["errors"] = "replace"
    if IS_WIN:
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    str_cmd = [str(c) for c in cmd]
    try:
        r = subprocess.run(str_cmd, **kw)
        stdout = r.stdout.strip() if capture and r.stdout else ""
        stderr = r.stderr.strip() if capture and r.stderr else ""
        return r.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except (FileNotFoundError, OSError, PermissionError, UnicodeDecodeError) as exc:
        return -1, "", str(exc)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — DEVICE DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AppleDevice:
    udid:         str
    display_name: str = "Unknown iPhone/iPad"
    product_type: str = ""
    ios_version:  str = ""
    paired:       bool = True
    tools_found:  list[str] = field(default_factory=list)


def list_connected_devices(tools_dir: Path | None = None) -> list[AppleDevice]:
    """
    Return a list of currently connected, trusted Apple devices.

    Uses (in order): idevice_id → ideviceinfo
    Falls back to Windows iTunes/WMI enumeration if CLI tools are absent.
    """
    global _TOOLS_DIR
    if tools_dir:
        _TOOLS_DIR = tools_dir

    devices: list[AppleDevice] = []

    # ── idevice_id -l ───────────────────────────────────────────────────
    idevice_id = _find_tool("idevice_id")
    if idevice_id:
        rc, stdout, _ = _run([idevice_id, "-l"])
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                udid = line.strip()
                if len(udid) >= 20:
                    dev = AppleDevice(udid=udid)
                    dev.tools_found.append("idevice_id")
                    _enrich_device(dev, tools_dir)
                    devices.append(dev)

    # ── Windows fallback: WMI / registry ────────────────────────────────
    if not devices and IS_WIN:
        devices = _windows_enumerate_devices()

    return devices


def _enrich_device(dev: AppleDevice, tools_dir: Path | None) -> None:
    """Fill in display_name, product_type, ios_version using ideviceinfo."""
    ideviceinfo = _find_tool("ideviceinfo")
    if not ideviceinfo:
        return
    dev.tools_found.append("ideviceinfo")

    fields_wanted = {
        "DeviceName":    "display_name",
        "ProductType":   "product_type",
        "ProductVersion":"ios_version",
    }
    rc, stdout, _ = _run([ideviceinfo, "-u", dev.udid], timeout=10)
    if rc != 0 or not stdout:
        return

    for line in stdout.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key in fields_wanted:
                setattr(dev, fields_wanted[key], val)

    if dev.product_type and not dev.display_name.startswith("Unknown"):
        pass
    elif dev.product_type:
        dev.display_name = dev.product_type


def _windows_enumerate_devices() -> list[AppleDevice]:
    """
    Enumerate iTunes-paired Apple devices on Windows via WMI.
    Only used when idevice_id is not available.
    """
    try:
        rc, stdout, _ = _run(
            ["powershell", "-NoProfile", "-Command",
             "Get-PnpDevice -Class 'USB' | Where-Object {$_.FriendlyName -like '*Apple*'} | "
             "Select-Object -ExpandProperty InstanceId"],
            timeout=8
        )
        if rc != 0 or not stdout:
            return []
        devices: list[AppleDevice] = []
        # UDIDs appear in InstanceId either as a 40-char hex string (devices
        # up to iPhone 8/X, pre-2018) or as the modern 8+16 hex format used
        # by iPhone XS and every device since ("00008030-001A0CAE0C12002E",
        # sometimes without the dash). The old regex only matched the
        # legacy format, so no device released since 2018 was ever found
        # via this Windows fallback path.
        udid_pat = re.compile(
            r"(?<![0-9A-Fa-f])("
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}"  # modern, with dash
            r"|[0-9A-Fa-f]{24}"                 # modern, no dash
            r"|[0-9A-Fa-f]{40}"                 # legacy
            r")(?![0-9A-Fa-f])"
        )
        for line in stdout.splitlines():
            m = udid_pat.search(line)
            if m:
                udid = m.group(1)
                if "-" not in udid and len(udid) == 24:
                    udid = f"{udid[:8]}-{udid[8:]}"
                devices.append(AppleDevice(
                    udid=udid,
                    display_name="Apple Device (iTunes)",
                ))
        return devices
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — PULL METHODS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PullResult:
    """Result of a panic log pull operation."""
    success:      bool
    method:       str           # "idevicecrashreport" | "idevicediagnostics" | "manual" etc.
    files:        list[Path]    = field(default_factory=list)
    error:        str           = ""
    udid:         str           = ""
    bytes_pulled: int           = 0


def pull_panic_logs(
    udid:       str,
    dest_dir:   Path,
    tools_dir:  Path | None = None,
    progress_cb: "callable[[str], None] | None" = None,
) -> PullResult:
    """
    Pull all panic-related files from a connected Apple device.

    Tries methods in priority order:
      1. idevicecrashreport (pulls panic-full + .ips analytics)
      2. idevicecrashreport --base64 (panic-base blob)
      3. idevicediagnostics (analytics/sysdiagnose bundle)

    Returns a PullResult with all collected file paths.
    """
    global _TOOLS_DIR
    if tools_dir:
        _TOOLS_DIR = tools_dir

    dest_dir.mkdir(parents=True, exist_ok=True)

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)
        log.info("[PanicPull] %s", msg)

    result = PullResult(success=False, method="none", udid=udid)

    # ── Method 1: idevicecrashreport (primary) ───────────────────────────
    tool = _find_tool("idevicecrashreport")
    if tool:
        _cb(f"Pulling panic logs via idevicecrashreport …")
        ok, files = _pull_via_crashreport(tool, udid, dest_dir, _cb)
        if ok and files:
            result.success = True
            result.method  = "idevicecrashreport"
            result.files   = files
            result.bytes_pulled = sum(f.stat().st_size for f in files if f.exists())
            _cb(f"✓  Pulled {len(files)} file(s) via idevicecrashreport")
            return result
        _cb("idevicecrashreport returned no panic files — trying panic-base …")

    # ── Method 2: idevicecrashreport --base64 (panic-base blob) ─────────
    if tool:
        _cb("Trying panic-base (base64-encoded blob) …")
        ok, files = _pull_base64_blob(tool, udid, dest_dir, _cb)
        if ok and files:
            result.success = True
            result.method  = "idevicecrashreport-base64"
            result.files   = files
            result.bytes_pulled = sum(f.stat().st_size for f in files if f.exists())
            _cb(f"✓  Pulled panic-base blob ({result.bytes_pulled} bytes)")
            return result

    # ── Method 3: idevicediagnostics (analytics / sysdiagnose) ──────────
    diag_tool = _find_tool("idevicediagnostics")
    if diag_tool:
        _cb("Attempting idevicediagnostics pull for analytics panics …")
        ok, files = _pull_via_diagnostics(diag_tool, udid, dest_dir, _cb)
        if ok and files:
            result.success = True
            result.method  = "idevicediagnostics"
            result.files   = files
            result.bytes_pulled = sum(f.stat().st_size for f in files if f.exists())
            _cb(f"✓  Pulled {len(files)} diagnostics file(s)")
            return result

    # ── No tools found or all methods failed ────────────────────────────
    if not tool and not diag_tool:
        result.error = (
            "libimobiledevice tools not found.\n\n"
            "Install with:\n"
            "  • macOS:   brew install libimobiledevice\n"
            "  • Linux:   sudo apt install libimobiledevice-utils\n"
            "  • Windows: bundle idevicecrashreport.exe in tools/\n\n"
            "Or place files manually in the tools/ folder next to PanicLab."
        )
    else:
        result.error = (
            "No panic logs found on device.\n\n"
            "Make sure:\n"
            "  • Device is connected and unlocked\n"
            "  • Device has been trusted (tap 'Trust' on device)\n"
            "  • Device has panicked at least once since last restore\n\n"
            "You can also drag-and-drop a .ips or .panic file directly."
        )

    return result


def _pull_via_crashreport(
    tool: Path, udid: str, dest: Path,
    cb: "callable[[str], None]"
) -> tuple[bool, list[Path]]:
    """
    Run: idevicecrashreport -u <udid> -e <dest>
    The -e/--extract flag dumps all CrashReporter entries to dest/.
    """
    # Try modern flag first (-e), fall back to --extract
    for flag in ["-e", "--extract"]:
        rc, stdout, stderr = _run(
            [tool, "-u", udid, flag, str(dest)],
            timeout=60,
        )
        if rc == 0:
            files = _collect_panic_files(dest)
            if files:
                return True, files
        elif "unknown option" in stderr.lower():
            continue
        # rc != 0 but not an unknown-option error: device issue
        if stderr:
            cb(f"  crashreport stderr: {stderr[:200]}")
        break

    files = _collect_panic_files(dest)
    return bool(files), files


def _pull_base64_blob(
    tool: Path, udid: str, dest: Path,
    cb: "callable[[str], None]"
) -> tuple[bool, list[Path]]:
    """
    Some versions of idevicecrashreport can emit a base64-encoded panic blob.
    We capture stdout and write it as panic-base.txt for the analyzer.
    """
    # Try: idevicecrashreport -u <udid> (stdout mode, no -e flag)
    rc, stdout, stderr = _run([tool, "-u", udid], timeout=30)

    if rc != 0 or not stdout:
        return False, []

    # Heuristic: if stdout looks like base64 or raw panic text
    stripped = stdout.strip().replace("\n", "").replace("\r", "")
    is_b64   = bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped) and len(stripped) > 100)
    is_panic = any(kw in stdout for kw in ("panic(cpu", "AppleNAND", "panicString", "iBoot"))

    if not (is_b64 or is_panic):
        return False, []

    out_path = dest / "panic-base.txt"
    out_path.write_text(stdout, encoding="utf-8", errors="replace")

    # If it's base64, also write the decoded version for raw preview
    if is_b64:
        try:
            decoded = base64.b64decode(stripped)
            if decoded[:2] == b"\x1f\x8b":
                decoded = gzip.decompress(decoded)
            decoded_path = dest / "panic-base-decoded.txt"
            decoded_path.write_bytes(decoded)
            return True, [out_path, decoded_path]
        except Exception:
            pass

    return True, [out_path]


def _pull_via_diagnostics(
    tool: Path, udid: str, dest: Path,
    cb: "callable[[str], None]"
) -> tuple[bool, list[Path]]:
    """
    idevicediagnostics can request a sysdiagnose or diagnostic bundle.
    We try the 'diagnostics All' command which includes panic logs.
    """
    rc, stdout, stderr = _run(
        [tool, "-u", udid, "diagnostics", "All"],
        timeout=120,
    )

    if rc != 0:
        cb(f"  idevicediagnostics failed (rc={rc}): {stderr[:200]}")
        return False, []

    # Write raw output as analytics-diagnostics.txt
    if stdout:
        out_path = dest / "analytics-diagnostics.txt"
        out_path.write_text(stdout, encoding="utf-8", errors="replace")

        # Check if it looks like panic/diagnostic data
        if any(kw in stdout for kw in ("panic", "Diagnostic", "IOKit", "AppleNAND")):
            return True, [out_path]

    files = _collect_panic_files(dest)
    return bool(files), files


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — FILE COLLECTION & CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

# Source type tags for pulled files
_SOURCE_TAGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.ips$",                 re.I), "analytics"),
    (re.compile(r"panic-full",             re.I), "panic-full"),
    (re.compile(r"panic-base",             re.I), "panic-base"),
    (re.compile(r"sysdiagnose|sysd",       re.I), "sysdiagnose"),
    (re.compile(r"\.panic$",               re.I), "panic-full"),
    (re.compile(r"DiagnosticMessages",     re.I), "analytics"),
    (re.compile(r"analytics",              re.I), "analytics"),
]


def _collect_panic_files(directory: Path) -> list[Path]:
    """
    Recursively find panic-relevant files in a directory.
    Prioritises .ips and .panic files over plain .txt/.log.
    """
    found: list[Path] = []
    for p in directory.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        ext  = p.suffix.lower()
        if ext in _PANIC_EXTENSIONS or any(kw in name for kw in _PANIC_KEYWORDS):
            found.append(p)

    # Sort: .ips first, then .panic, then others
    def _rank(p: Path) -> int:
        ext = p.suffix.lower()
        if ext == ".ips":    return 0
        if ext == ".panic":  return 1
        if "panic" in p.name.lower(): return 2
        return 3

    return sorted(found, key=_rank)


def classify_pulled_file(path: Path) -> str:
    """Return a source-type label for a pulled file ('panic-full', 'analytics', etc.)"""
    name = path.name
    for pat, tag in _SOURCE_TAGS:
        if pat.search(name):
            return tag
    # Check file content header
    try:
        header = path.read_bytes()[:512].decode("utf-8", errors="replace")
        if "panicString" in header or "bug_type" in header:
            return "analytics"
        if "panic(cpu" in header.lower() or "AppleNAND" in header:
            return "panic-full"
        stripped = header.strip().replace("\n", "").replace("\r", "")
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped) and len(stripped) > 200:
            return "panic-base"
    except Exception:
        pass
    return "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — TOOL AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ToolStatus:
    name:      str
    path:      Path | None
    available: bool
    version:   str = ""


def check_tools(tools_dir: Path | None = None) -> list[ToolStatus]:
    """
    Check which libimobiledevice tools are available.
    Returns a list of ToolStatus objects for the UI to display.
    """
    global _TOOLS_DIR
    if tools_dir:
        _TOOLS_DIR = tools_dir

    tools_to_check = [
        "idevicecrashreport",
        "idevice_id",
        "ideviceinfo",
        "idevicediagnostics",
        "idevicepair",
        "idevicebackup2",
    ]

    statuses: list[ToolStatus] = []
    for name in tools_to_check:
        path = _find_tool(name)
        version = ""
        if path:
            rc, out, _ = _run([path, "--version"], timeout=4)
            if rc == 0 and out:
                version = out.splitlines()[0][:80]
        statuses.append(ToolStatus(
            name=name,
            path=path,
            available=path is not None,
            version=version,
        ))

    return statuses


def install_instructions() -> str:
    """Return platform-specific installation instructions for libimobiledevice."""
    if IS_MAC:
        return (
            "Install libimobiledevice:\n"
            "  brew install libimobiledevice\n\n"
            "Then trust your device:\n"
            "  idevicepair pair"
        )
    elif IS_LIN:
        return (
            "Install libimobiledevice:\n"
            "  sudo apt install libimobiledevice-utils   # Debian/Ubuntu\n"
            "  sudo dnf install libimobiledevice         # Fedora\n\n"
            "Then trust your device:\n"
            "  idevicepair pair"
        )
    else:  # Windows
        return (
            "Bundle libimobiledevice tools:\n"
            "  1. Download from https://github.com/libimobiledevice-win32/\n"
            "  2. Place idevicecrashreport.exe + idevice_id.exe + ideviceinfo.exe\n"
            "     in the tools/ folder next to PanicLab\n\n"
            "  iTunes or Apple Devices app must also be installed so\n"
            "  the Apple Mobile Device driver is present."
        )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — COMBINED TEXT BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_combined_text(files: list[Path]) -> tuple[str, str]:
    """
    Read and combine all pulled panic files into one text blob.
    Returns (combined_text, source_label).
    source_label is the label for the first / most relevant file.
    """
    from apple_analyzer import _decode_panic_base, _read_ips_json, AppleSourceType

    parts: list[str] = []
    source_label = "pulled-panic"

    for i, f in enumerate(files):
        try:
            raw  = f.read_bytes()
            text = _decode_panic_base(raw)
            tag  = classify_pulled_file(f)

            # Unwrap IPS JSON
            if tag == "analytics" or f.suffix.lower() == ".ips":
                if text.lstrip().startswith("{"):
                    text = _read_ips_json(text)

            parts.append(f"=== {f.name}  [{tag}] ===\n{text}")

            if i == 0:
                source_label = f.name
        except Exception as exc:
            log.warning("Could not read pulled file %s: %s", f, exc)

    return "\n\n".join(parts), source_label
