"""
apple_analyzer.py — PanicLab Apple Panic Log Analyzer
======================================================
Supports:
  - panic-full   (raw kernel panic text, pulled via idevicecrashreport)
  - panic-base   (base64-encoded / binary panic blob from CrashReporter)
  - analytics    (ips / JSON-wrapped analytics panic reports)
  - sysdiagnose  (panic files extracted from sysdiagnose .tar.gz)

Detects hardware issues involving:
  - NAND / storage
  - Battery / power
  - Face ID (Biometric Secure Enclave)
  - Display (backlight / TCON / panel)
  - Charging (PMIC / USB-C)
  - Audio (codec / speaker amp)
  - Baseband (cellular modem)

Output per Finding:
  - category    : AppleCategory
  - title       : str
  - severity    : Severity  (critical | high | medium | low)
  - confidence  : int  0-100
  - evidence    : list[str]   (raw snippets with surrounding context)
  - suggestions : list[str]   (actionable repair steps)
  - source_type : AppleSourceType
  - line_refs   : list[int]
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Iterator


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class AppleCategory(StrEnum):
    NAND      = "NAND/Storage"
    BATTERY   = "Battery/Power"
    FACE_ID   = "Face ID"
    DISPLAY   = "Display"
    CHARGING  = "Charging"
    AUDIO     = "Audio"
    BASEBAND  = "Baseband"
    KERNEL    = "Kernel"
    UNKNOWN   = "Unknown"


class AppleSourceType(StrEnum):
    PANIC_FULL    = "panic-full"
    PANIC_BASE    = "panic-base"
    ANALYTICS     = "analytics"
    SYSDIAGNOSE   = "sysdiagnose"
    IPS           = "ips"
    UNKNOWN       = "unknown"


@dataclass
class Finding:
    category:    AppleCategory
    title:       str
    severity:    Severity
    confidence:  int               # 0-100
    evidence:    list[str]         = field(default_factory=list)
    suggestions: list[str]         = field(default_factory=list)
    source_type: AppleSourceType   = AppleSourceType.UNKNOWN
    line_refs:   list[int]         = field(default_factory=list)

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 85: return "Very High"
        if self.confidence >= 70: return "High"
        if self.confidence >= 50: return "Medium"
        if self.confidence >= 30: return "Low"
        return "Very Low"


@dataclass
class AppleAnalysisResult:
    source_type:   AppleSourceType
    findings:      list[Finding]
    raw_preview:   str          # first ~120 lines for display
    file_name:     str
    total_lines:   int
    is_panic_log:  bool         # False → not recognised as Apple panic
    device_info:   dict[str, str] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — SOURCE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

# Markers that appear in genuine Apple kernel panic text
_PANIC_FULL_MARKERS = re.compile(
    r"(panic\(cpu \d+|Kernel Extensions in backtrace|"
    r"BSD process name corresponding|"
    r"Mac OS version:|Kernel version:|"
    r"AppleBCMWLAN|AppleNAND|AppleStorageDrivers|"
    r"iBoot version:|RELEASE_ARM|"
    r"Panicked task|paniclog version)",
    re.I,
)

# IPS / analytics panic — JSON wrapper with "panicString" or "bug_type"
_IPS_MARKERS = re.compile(
    r"(\"panicString\"|\"bug_type\"\s*:\s*\"210\"|"
    r"\"incident_id\"|\"os_version\"\s*:|"
    r"\"share_with_apple\"|\"ips_metadata\")",
    re.I,
)

# Sysdiagnose panic files — extracted by sysdiagnose, live in panic/ subdir
_SYSDIAG_MARKERS = re.compile(
    r"(sysdiagnose|panic\.ips|panic-full|"
    r"ReportCrash.*AppleLogKit|"
    r"com\.apple\.CrashReporter)",
    re.I,
)

# Base64-encoded panic blob (idevicecrashreport --base64)
_BASE64_HINT = re.compile(r"^[A-Za-z0-9+/\r\n]+=*$", re.M)

# Definitive Apple panic indicators
_APPLE_INDICATORS = re.compile(
    r"(panic\(cpu|AppleNAND|iBoot version|Apple Panic|"
    r"panicString|Panicked task|RELEASE_ARM|"
    r"kernel\[\d+\]|com\.apple\.|IOKit|AppleSMC|"
    r"Kernel Extensions in backtrace|"
    r"BSD process name|Exception state|"
    r"Debugger called)",
    re.I,
)


def classify_source(text: str) -> tuple[AppleSourceType, bool]:
    """
    Returns (AppleSourceType, is_panic_log).
    is_panic_log=False → file not recognised as an Apple panic log.
    """
    sample = text[:8000]
    hits = len(_APPLE_INDICATORS.findall(sample))

    if hits == 0:
        return AppleSourceType.UNKNOWN, False

    # IPS / analytics JSON wrapper
    if _IPS_MARKERS.search(sample):
        return AppleSourceType.IPS, True

    # Sysdiagnose bundle reference
    if _SYSDIAG_MARKERS.search(sample):
        return AppleSourceType.SYSDIAGNOSE, True

    # panic-base: base64-encoded blob (written by apple_panic_pull as panic-base.txt)
    # Detect by section header injected during pull, or raw base64 content
    if re.search(r"\[panic-base\]", sample, re.I):
        return AppleSourceType.PANIC_BASE, True
    stripped = sample.strip().replace("\n", "").replace("\r", "")
    if len(stripped) > 200 and re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped):
        return AppleSourceType.PANIC_BASE, True

    # Raw panic-full text (idevicecrashreport plain output)
    if _PANIC_FULL_MARKERS.search(sample):
        return AppleSourceType.PANIC_FULL, True

    # Generic Apple panic text
    if hits >= 2:
        return AppleSourceType.PANIC_FULL, True

    return AppleSourceType.UNKNOWN, False


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — DEVICE INFO EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_device_info(text: str) -> dict[str, str]:
    """Pull model, iOS version, iBoot version, etc. from panic text."""
    info: dict[str, str] = {}
    patterns = {
        "OS Version":      re.compile(r"iPhone OS\s+([\d.]+)", re.I),
        "Kernel Version":  re.compile(r"Kernel version:\s*(.+)", re.I),
        "iBoot Version":   re.compile(r"iBoot version:\s*(.+)", re.I),
        "Model":           re.compile(r"(iPhone\d{1,2},\d+|iPad\d+,\d+|iPod\d+,\d+)", re.I),
        "Build":           re.compile(r"\b([A-Z]\d{2}[A-Z]\d{4}[a-z]?)\b"),
        "CPU":             re.compile(r"(RELEASE_ARM(?:_T\w+)?)", re.I),
        "Panic Type":      re.compile(r"(panic\(cpu\s+\d+[^)]*\))", re.I),
    }
    for key, pat in patterns.items():
        m = pat.search(text[:6000])
        if m:
            info[key] = m.group(1).strip()[:120]

    # IPS JSON fields
    try:
        obj = json.loads(text)
        for k, jk in [("OS Version", "os_version"), ("Model", "product_name"),
                       ("Build", "build_version"), ("Incident", "incident_id")]:
            if jk in obj:
                info[k] = str(obj[jk])[:120]
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return info


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — PATTERN LIBRARY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Pattern:
    regex:       re.Pattern
    category:    AppleCategory
    title:       str
    severity:    Severity
    confidence:  int
    suggestions: list[str]


def _p(pattern: str, cat: AppleCategory, title: str, sev: Severity,
       conf: int, suggestions: list[str]) -> Pattern:
    return Pattern(re.compile(pattern, re.I | re.M), cat, title, sev, conf, suggestions)


PATTERNS: list[Pattern] = [

    # ── NAND / Storage ────────────────────────────────────────────────────
    _p(
        r"AppleNAND|NAND.*error|nand.*fault|nand.*fail|"
        r"ANS\d?.*error|ANS\d?.*fault|AppleNVMeController.*error|"
        r"NVMe.*timeout|NVMe.*fatal|nvme.*reset|"
        r"AppleStorageDrivers.*panic|"
        r"com\.apple\.driver\.AppleNAND",
        AppleCategory.NAND,
        "NAND / NVMe Storage Error",
        Severity.CRITICAL, 92,
        [
            "Replace NAND flash IC — BGA reball or full chip swap required",
            "Check NAND power rails (VCCQ 1.2V, VCC 3.3V) with multimeter under load",
            "Inspect NAND clock and data lanes for shorts or opens on signal layer",
            "Attempt DFU restore; if it fails with error 4013/4014, NAND is hardware-dead",
            "If only metadata is corrupt, JTAG NAND programmer may recover user data",
        ],
    ),
    _p(
        r"io.*error.*nand|nand.*io.*error|"
        r"SMC.*storage|storage.*driver.*panic|"
        r"AppleEmbeddedNVMeHostController.*Timeout|"
        r"ANE.*error|apfs.*fatal|apfs.*panic|hfs.*panic",
        AppleCategory.NAND,
        "Storage Controller / APFS Panic",
        Severity.CRITICAL, 88,
        [
            "APFS/HFS journal abort usually follows a prior NAND I/O failure",
            "Attempt DFU restore; persistent failure → NAND hardware replacement",
            "Check for corrosion on NAND balls via X-ray before reballing",
            "Back up data via NAND-off programmer if device boots to DFU only",
        ],
    ),
    _p(
        r"wear.*leveling|bad.*block.*nand|nand.*wear|"
        r"flash.*ecc.*error|nand.*uncorrectable",
        AppleCategory.NAND,
        "NAND Wear / ECC Failure",
        Severity.HIGH, 85,
        [
            "NAND has reached end-of-life wear level — replacement recommended",
            "Perform full backup immediately; device may become unbootable soon",
            "DFU restore may temporarily stabilise device; NAND replacement is the fix",
        ],
    ),

    # ── Battery / Power ───────────────────────────────────────────────────
    _p(
        r"ApplePMU.*panic|AppleSMC.*panic|PMIC.*panic|"
        r"gasgauge.*error|battery.*fatal|"
        r"PMU.*fault|power.*management.*panic|"
        r"AppleA\d+PMGR.*panic|PMGR.*error",
        AppleCategory.BATTERY,
        "PMU / Battery Management Panic",
        Severity.CRITICAL, 91,
        [
            "Replace battery — measure voltage (should be 3.0–4.35V) and internal resistance",
            "Check PMIC (Dialog/Qualcomm) output rails with oscilloscope under load",
            "Inspect battery connector pins and flex cable for oxidation or damage",
            "If PMIC is shorted: isolate by disconnecting battery and measuring rails cold",
            "Replace PMIC IC if rail output remains incorrect after battery swap",
        ],
    ),
    _p(
        r"AppleSmartBattery.*fail|battery.*capacity.*critical|"
        r"low.*battery.*shutdown|UVLO|under.*voltage.*lockout|"
        r"batt.*voltage.*drop|SOC.*critical",
        AppleCategory.BATTERY,
        "Battery Undervoltage / UVLO Shutdown",
        Severity.HIGH, 85,
        [
            "Battery cannot sustain load — replace battery",
            "Measure open-circuit voltage (>3.6V healthy) and ESR (<100 mΩ healthy)",
            "Check for swollen battery causing physical board flex",
            "Inspect main power connector for intermittent contact",
        ],
    ),
    _p(
        r"AppleARMPlatform.*sleep.*fail|"
        r"sleep.*wake.*panic|"
        r"wakeup.*failure|"
        r"hibernat.*error",
        AppleCategory.BATTERY,
        "Sleep / Wake Power Fault",
        Severity.MEDIUM, 72,
        [
            "Sleep-wake failures can indicate battery or PMIC instability during S3/S5 transitions",
            "Test with known-good battery; if resolved, replace battery",
            "If panic persists: inspect power rails during sleep entry with oscilloscope",
        ],
    ),

    # ── Face ID ───────────────────────────────────────────────────────────
    _p(
        r"AppleBiometricKit.*panic|"
        r"SEP.*panic|SEP.*fault|SEP.*error|"
        r"SecureEnclave.*panic|"
        r"FaceDetection.*panic|FaceID.*panic|"
        r"AppleD2050|AppleFaceDetector|"
        r"TrueDepth.*error|TrueDepth.*panic",
        AppleCategory.FACE_ID,
        "Face ID / Secure Enclave Panic",
        Severity.CRITICAL, 90,
        [
            "Face ID hardware panic — replace TrueDepth camera module",
            "Do NOT repair/replace front camera on Face ID models without original parts; "
            "Face ID will permanently fail (paired to logic board)",
            "After screen replacement, restore via DFU to re-pair SEP; if panic persists, "
            "the Secure Enclave Processor (SEP) on main SoC may be damaged",
            "Check TrueDepth FPC connector for bent pins or corrosion",
            "If SEP itself is damaged, device requires main board replacement",
        ],
    ),
    _p(
        r"IrisCamera.*error|DotProjector.*fault|"
        r"proximity.*sensor.*panic|"
        r"flood.*illuminator.*error",
        AppleCategory.FACE_ID,
        "TrueDepth Sensor Fault",
        Severity.HIGH, 82,
        [
            "Individual TrueDepth component failure (dot projector / flood illuminator / IR camera)",
            "Replace entire TrueDepth module — components are calibrated as a unit",
            "Check FPC cable for physical damage (common after screen drops)",
            "Inspect connector J2700/J3800 area for corrosion from liquid damage",
        ],
    ),

    # ── Display ───────────────────────────────────────────────────────────
    _p(
        r"AppleCLCD.*panic|AppleDCP.*panic|DCP.*fault|DCP.*error|"
        r"backlight.*driver.*panic|backlight.*fail|"
        r"AppleFramebuffer.*panic|TCON.*error|TCON.*panic|"
        r"display.*controller.*panic|LCM.*panic|"
        r"ApplePPM.*panic|PPM.*display.*error",
        AppleCategory.DISPLAY,
        "Display Controller / Backlight Panic",
        Severity.CRITICAL, 89,
        [
            "Display driver panic — replace display assembly",
            "On iPhone 13+, recalibrate True Tone after screen swap using proprietary tool; "
            "third-party screens will not cause SEP panic but will lose True Tone",
            "Inspect TCON board on LCD models for shorted capacitors (cold-joint reflow may fix)",
            "Measure backlight LED boost rail (20–40V on probe pad) — no voltage = dead IC",
            "Check backlight coil for open circuit; replace if DCR out of spec",
            "On OLED models: DCP panic after screen swap usually means non-genuine panel",
        ],
    ),
    _p(
        r"AppleT\d+MIPI.*panic|MIPI.*DSI.*error|"
        r"panel.*init.*fail|display.*init.*timeout|"
        r"AppleDisplayPipe.*panic",
        AppleCategory.DISPLAY,
        "MIPI DSI / Display Panel Init Failure",
        Severity.HIGH, 83,
        [
            "MIPI display bus failure — replace display assembly",
            "Inspect MIPI flex cable connector for bent/broken pins",
            "On iPad: check digitizer connector; MIPI and touch share the same FPC route",
            "Measure 1.8V DSI power rail; low voltage = regulator failure on display board",
        ],
    ),

    # ── Charging ──────────────────────────────────────────────────────────
    _p(
        r"AppleUSBPD.*panic|USBC.*PD.*fault|"
        r"Tristar.*error|Hydra.*error|ACE.*error|"
        r"charging.*IC.*panic|ONSEMI.*panic|"
        r"CD3215.*fault|CD3217.*fault|"
        r"AppleUSBTypeCPort.*panic|"
        r"VBUS.*overvoltage|VBUS.*fault",
        AppleCategory.CHARGING,
        "USB-C / Charging IC Panic",
        Severity.CRITICAL, 90,
        [
            "Replace Tristar/Hydra USB-C controller IC (Meson / ACE3 on newer models)",
            "Measure VBUS (should be 5V from charger, up to 20V on PD) — no voltage = dead charger IC",
            "Check for shorted D+/D- lines caused by liquid ingress into Lightning/USB-C port",
            "On iPhone 11+: ACE3 (CD3215/CD3217) handles PD; requires micro-soldering to replace",
            "If only slow-charging: check for bent pins in port; replace port assembly",
            "Clean charging port with isopropyl alcohol and soft brush before IC replacement",
        ],
    ),
    _p(
        r"AppleLightning.*panic|lightning.*controller.*fail|"
        r"dock.*connector.*error",
        AppleCategory.CHARGING,
        "Lightning Controller Fault",
        Severity.HIGH, 85,
        [
            "Tristar (U2) or Hydra chip failure — replace IC",
            "Tristar replacement requires BGA micro-soldering under microscope",
            "First clean Lightning port thoroughly — debris causes ~40% of charging failures",
            "Measure 3.3V on PP3V3_USB line; absent voltage = Tristar fault",
            "After Tristar replacement, verify device charges and syncs at USB 2.0 speed",
        ],
    ),

    # ── Audio ──────────────────────────────────────────────────────────────
    _p(
        r"AppleAudio.*panic|audio.*driver.*panic|"
        r"Cirrus.*Logic.*panic|CS42.*panic|"
        r"SoundSoC.*panic|AppleSmartAudio.*panic|"
        r"TAS.*amplifier.*fault|TAS\d+.*panic|"
        r"speaker.*amp.*fault|audio.*codec.*panic|"
        r"AppleHDA.*panic",
        AppleCategory.AUDIO,
        "Audio Codec / Amplifier Panic",
        Severity.HIGH, 86,
        [
            "Replace audio codec IC (Cirrus Logic CS42Lxx) or speaker amplifier (TI TAS256x)",
            "Measure AVDD (1.8V) and DVDD (1.2V) rails on codec — absent = regulator fault",
            "Check I2S/I2C bus lines for shorts on audio flex cable",
            "On iPhone 7–X: audio IC (U3101) failure also disables Touch ID loop — replace IC",
            "Inspect speaker grille for blockage and speaker coil for mechanical damage before IC swap",
            "On liquid damage: audio IC corrosion is common — clean with ultrasonic bath first",
        ],
    ),
    _p(
        r"microphone.*error|mic.*fault|"
        r"audio.*input.*panic|MEMS.*mic.*fail|"
        r"PDM.*mic.*error",
        AppleCategory.AUDIO,
        "Microphone Fault",
        Severity.MEDIUM, 74,
        [
            "MEMS microphone failure — replace microphone (SMD rework)",
            "Check audio input FPC cable for damage on fold points",
            "Clean microphone port with compressed air before disassembly",
            "Measure PDM clock and data lines for signal integrity",
        ],
    ),

    # ── Baseband ──────────────────────────────────────────────────────────
    _p(
        r"AppleBaseband.*panic|baseband.*fatal|"
        r"baseband.*crash|mdm9625.*error|"
        r"XMM\d+.*fault|Intel.*baseband.*panic|"
        r"Qualcomm.*baseband.*panic|QSC\d+.*error|"
        r"BB_CPU.*panic|rf.*frontend.*panic|"
        r"commcenter.*panic|BasebandAPSS.*crash",
        AppleCategory.BASEBAND,
        "Baseband / Cellular Modem Panic",
        Severity.CRITICAL, 91,
        [
            "Replace baseband CPU (separate BGA chip on most iPhone models, "
            "embedded in package on newer A-series)",
            "Check baseband power supply (1.8V BB_VREG rails) — drooping under TX load = replace PMIC",
            "Inspect RF antenna connectors for loose or corroded contacts",
            "Liquid damage to baseband: clean with ultrasonic bath; replace IC if corroded",
            "On iPhone 12+: Qualcomm SDX55/SDX65 modem — micro-BGA replacement required",
            "After baseband replacement, restore in DFU to re-provision carrier settings",
        ],
    ),
    _p(
        r"no.*sim.*detected|SIM.*card.*error|SIM.*fault|"
        r"baseband.*no.*signal|cellular.*offline.*panic",
        AppleCategory.BASEBAND,
        "SIM / Baseband Connectivity Fault",
        Severity.HIGH, 78,
        [
            "Check SIM tray and SIM card pins for corrosion or damage",
            "Inspect SIM reader flex cable — replace if bent or corroded",
            "If SIM detected but no signal: check RF frontend and antenna tuner ICs",
            "Baseband firmware restore via DFU may resolve transient baseband faults",
        ],
    ),
    _p(
        r"AppleWWAN.*panic|wwan.*error|wwan.*firmware.*fault",
        AppleCategory.BASEBAND,
        "WWAN Firmware / Driver Panic",
        Severity.HIGH, 80,
        [
            "Baseband firmware crash — attempt DFU restore to re-flash baseband firmware",
            "If panic recurs after restore: replace baseband IC",
            "Verify carrier unlock status is preserved after firmware reflash",
        ],
    ),

    # ── Kernel / Generic ──────────────────────────────────────────────────
    _p(
        r"panic\(cpu \d+.*\):\s*\w+.*null pointer|"
        r"panic.*NULL.*dereference|"
        r"kernel.*panic.*address\s+0x0",
        AppleCategory.KERNEL,
        "Kernel NULL Pointer Dereference",
        Severity.HIGH, 78,
        [
            "Software kernel bug — update to latest iOS/iPadOS",
            "If panic follows hardware repair: re-seat all connectors",
            "Collect full panic log and report to Apple via Feedback Assistant",
        ],
    ),
    _p(
        r"watchdog.*timeout.*panic|WDT.*expired|"
        r"hardware.*watchdog.*fired|RTKit.*watchdog",
        AppleCategory.KERNEL,
        "Hardware Watchdog Timeout",
        Severity.HIGH, 82,
        [
            "Watchdog fired — SoC sub-system (RTKit co-processor) stopped responding",
            "Common causes: overheating, NAND/RAM hardware fault, or failed driver",
            "Check thermal throttling logs; if device runs hot, inspect thermal pad on SoC",
            "DFU restore may resolve if caused by corrupted firmware",
            "Persistent watchdog panics with hardware evidence → main board replacement",
        ],
    ),
    _p(
        r"double fault|double exception|"
        r"AppleExceptionHandler.*fatal|"
        r"unhandled exception|synchronous abort",
        AppleCategory.KERNEL,
        "CPU / ARM Exception Fault",
        Severity.CRITICAL, 87,
        [
            "Unhandled ARM exception — can indicate RAM or SoC fault",
            "Run Apple Diagnostics (hold Volume Up + Volume Down + Side button on boot)",
            "If hardware fault confirmed: main board replacement required",
            "If exception is consistent after iOS restore: SoC package fault",
        ],
    ),
    _p(
        r"RTKit.*panic|RTKit.*error|coprocessor.*panic|"
        r"ISP.*panic|AppleSEP.*coprocessor.*error",
        AppleCategory.KERNEL,
        "RTKit Co-Processor Panic",
        Severity.HIGH, 83,
        [
            "RTKit co-processor failure (ISP, ANE, SEP, or AOP)",
            "DFU restore often resolves firmware-level RTKit panics",
            "If panic recurs: identify which co-processor (ISP=camera, ANE=neural engine, SEP=security)",
            "SEP panic after logic board swap is expected — restore in DFU to re-pair",
        ],
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — CONTEXT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_context(lines: list[str], match_line: int,
                     context: int = 5) -> list[str]:
    """Return context_lines before and after match_line, plus the match itself."""
    start = max(0, match_line - context)
    end   = min(len(lines), match_line + context + 1)
    result: list[str] = []
    for i in range(start, end):
        prefix = ">>> " if i == match_line else "    "
        result.append(f"{prefix}{i + 1:>6}: {lines[i]}")
    return result


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — DEDUPLICATION / MERGE
# ═══════════════════════════════════════════════════════════════════════════

def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings with the same (category, title).
    Keep the highest-confidence instance; accumulate evidence snippets.
    Sort by severity (critical → low) then confidence descending.
    """
    _SEV_ORDER = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2,   Severity.LOW: 3,
    }
    merged: dict[tuple, Finding] = {}

    for f in findings:
        key = (f.category, f.title)
        if key not in merged:
            merged[key] = f
        else:
            existing = merged[key]
            if f.confidence > existing.confidence:
                merged[key] = Finding(
                    category=existing.category,
                    title=existing.title,
                    severity=existing.severity,
                    confidence=f.confidence,
                    evidence=existing.evidence + f.evidence,
                    suggestions=existing.suggestions,
                    source_type=existing.source_type,
                    line_refs=existing.line_refs + f.line_refs,
                )
            else:
                merged[key] = Finding(
                    category=existing.category,
                    title=existing.title,
                    severity=existing.severity,
                    confidence=existing.confidence,
                    evidence=existing.evidence + f.evidence,
                    suggestions=existing.suggestions,
                    source_type=existing.source_type,
                    line_refs=existing.line_refs + f.line_refs,
                )

    result = list(merged.values())
    result.sort(key=lambda x: (_SEV_ORDER.get(x.severity, 99), -x.confidence))

    # Cap evidence to 4 snippets per finding
    for f in result:
        f.evidence = f.evidence[:4]

    return result


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — FILE READERS
# ═══════════════════════════════════════════════════════════════════════════

def _decode_panic_base(data: bytes) -> str:
    """
    Attempt to decode a panic-base blob.
    Tries: gzip → plain UTF-8 → base64 decode → base64+gzip.
    """
    # 1. gzip magic
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data).decode("utf-8", errors="replace")
        except Exception:
            pass

    # 2. plain text (UTF-8)
    try:
        text = data.decode("utf-8", errors="strict")
        if "panic" in text.lower() or "AppleNAND" in text:
            return text
    except UnicodeDecodeError:
        pass

    # 3. base64 decode
    try:
        decoded = base64.b64decode(data)
        # check if result is gzipped
        if decoded[:2] == b"\x1f\x8b":
            return gzip.decompress(decoded).decode("utf-8", errors="replace")
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Fallback: raw bytes as latin-1
    return data.decode("latin-1", errors="replace")


def _read_ips_json(text: str) -> str:
    """Extract panicString from IPS JSON wrapper, return combined text."""
    try:
        obj = json.loads(text)
        parts: list[str] = [text[:2000]]   # keep JSON header as context
        if "panicString" in obj:
            parts.append(obj["panicString"])
        if "stackshots" in obj:
            # Some IPS files embed crash frames as JSON array
            parts.append(json.dumps(obj["stackshots"], indent=2)[:4000])
        return "\n".join(parts)
    except (json.JSONDecodeError, ValueError, TypeError):
        return text


def _read_sysdiagnose_tar(path: Path) -> str:
    """
    Extract panic-related files from a sysdiagnose .tar.gz archive.
    Priority: panic/*.ips > panic/*.panic > panic-full > panic-base
    """
    collected: list[str] = []
    PRIORITY = ["panic/", "panic-full", "panic-base", "crashes/", "ips"]
    try:
        with tarfile.open(path, "r:gz") as tf:
            members = tf.getmembers()
            def _rank(m: tarfile.TarInfo) -> int:
                nl = m.name.lower()
                for i, kw in enumerate(PRIORITY):
                    if kw in nl:
                        return i
                return len(PRIORITY)
            for member in sorted(members, key=_rank):
                if member.isfile() and any(kw in member.name.lower() for kw in PRIORITY):
                    try:
                        f = tf.extractfile(member)
                        if f:
                            raw = f.read()
                            text = _decode_panic_base(raw)
                            collected.append(f"=== {member.name} ===\n{text}")
                            if sum(len(c) for c in collected) > 600_000:
                                break
                    except Exception:
                        continue
    except tarfile.TarError:
        pass
    return "\n".join(collected)


def _read_zip(path: Path) -> str:
    """Read panic files from a ZIP (e.g. sysdiagnose on older iOS)."""
    collected: list[str] = []
    PRIORITY = ["panic", "crash", "ips"]
    try:
        with zipfile.ZipFile(path, "r") as zf:
            def _rank(n: str) -> int:
                nl = n.lower()
                for i, kw in enumerate(PRIORITY):
                    if kw in nl:
                        return i
                return len(PRIORITY)
            for name in sorted(zf.namelist(), key=_rank):
                if any(kw in name.lower() for kw in PRIORITY):
                    try:
                        raw = zf.read(name)
                        text = _decode_panic_base(raw)
                        collected.append(f"=== {name} ===\n{text}")
                        if sum(len(c) for c in collected) > 500_000:
                            break
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        pass
    return "\n".join(collected)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — MAIN ANALYZER CLASS
# ═══════════════════════════════════════════════════════════════════════════

class ApplePanicAnalyzer:
    """
    Analyzes Apple panic logs across all supported source types.

    Usage:
        analyzer = ApplePanicAnalyzer()
        result   = analyzer.analyze_file(Path("panic.ips"))
    """

    def __init__(self, context_lines: int = 5, min_confidence: int = 40) -> None:
        self.context_lines   = context_lines
        self.min_confidence  = min_confidence

    # ── Public entry points ───────────────────────────────────────────────

    def analyze_file(self, path: Path) -> AppleAnalysisResult:
        """Analyze a single file — detects format automatically."""
        text, fname, detected_source = self._read_file(path)
        return self._analyze_text(text, fname, detected_source)

    def analyze_text(self, text: str, filename: str = "input",
                     source_hint: AppleSourceType = AppleSourceType.UNKNOWN) -> AppleAnalysisResult:
        """Analyze panic text already in memory (e.g. pulled via idevicecrashreport)."""
        return self._analyze_text(text, filename, source_hint)

    # ── File reader ───────────────────────────────────────────────────────

    def _read_file(self, path: Path) -> tuple[str, str, AppleSourceType]:
        """
        Return (text, filename, source_hint).
        Handles: .ips, .panic, .txt, .log, .gz, .tar.gz, .zip, binary blobs.
        """
        name   = path.name
        suffix = path.suffix.lower()
        stem   = path.stem.lower()

        # sysdiagnose .tar.gz
        if suffix == ".gz" and stem.endswith(".tar"):
            return _read_sysdiagnose_tar(path), name, AppleSourceType.SYSDIAGNOSE
        if suffix in {".tgz"}:
            return _read_sysdiagnose_tar(path), name, AppleSourceType.SYSDIAGNOSE

        # ZIP (older sysdiagnose or exported CrashReporter bundles)
        if suffix == ".zip":
            return _read_zip(path), name, AppleSourceType.UNKNOWN

        # Single gzip
        if suffix == ".gz":
            with gzip.open(path, "rb") as f:
                return _decode_panic_base(f.read()), name, AppleSourceType.UNKNOWN

        # Binary file — try decode
        raw = path.read_bytes()

        # IPS files are plain JSON text
        if suffix == ".ips":
            text = raw.decode("utf-8", errors="replace")
            # IPS can be just panicString or full JSON
            if text.lstrip().startswith("{"):
                return _read_ips_json(text), name, AppleSourceType.IPS
            return text, name, AppleSourceType.IPS

        # .panic extension
        if suffix == ".panic":
            text = _decode_panic_base(raw)
            return text, name, AppleSourceType.PANIC_FULL

        # Plain text / log
        if suffix in {".txt", ".log", ""}:
            text = raw.decode("utf-8", errors="replace")
            # Heuristic: if file looks like base64-encoded blob, decode it
            stripped = text.strip().replace("\n", "").replace("\r", "")
            if len(stripped) > 200 and re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped):
                try:
                    decoded = base64.b64decode(stripped)
                    text = _decode_panic_base(decoded)
                    return text, name, AppleSourceType.PANIC_BASE
                except Exception:
                    pass
            # Check for IPS JSON embedded in .txt
            if "panicString" in text or "bug_type" in text:
                return _read_ips_json(text), name, AppleSourceType.IPS
            return text, name, AppleSourceType.PANIC_FULL

        # Unknown — try binary decode
        return _decode_panic_base(raw), name, AppleSourceType.UNKNOWN

    # ── Core analysis ─────────────────────────────────────────────────────

    def _analyze_text(self, text: str, filename: str,
                      source_hint: AppleSourceType) -> AppleAnalysisResult:
        # 1. Classify source type
        classified_source, is_panic = classify_source(text)
        source_type = classified_source if source_hint == AppleSourceType.UNKNOWN else source_hint

        if not is_panic and source_hint == AppleSourceType.UNKNOWN:
            return AppleAnalysisResult(
                source_type=source_type,
                findings=[],
                raw_preview="\n".join(text.splitlines()[:120]),
                file_name=filename,
                total_lines=len(text.splitlines()),
                is_panic_log=False,
            )

        lines       = text.splitlines()
        total_lines = len(lines)
        raw_preview = "\n".join(lines[:120])

        # 2. Extract device metadata
        device_info = _extract_device_info(text)

        # 3. Run pattern library
        findings: list[Finding] = []
        for pat in PATTERNS:
            for match_obj in pat.regex.finditer(text):
                match_start = match_obj.start()
                line_no     = text[:match_start].count("\n")
                evidence    = _extract_context(lines, line_no, self.context_lines)
                findings.append(Finding(
                    category=pat.category,
                    title=pat.title,
                    severity=pat.severity,
                    confidence=pat.confidence,
                    evidence=evidence,
                    suggestions=list(pat.suggestions),
                    source_type=source_type,
                    line_refs=[line_no + 1],
                ))

        # 4. Merge, filter, sort
        findings = _merge_findings(findings)
        findings = [f for f in findings if f.confidence >= self.min_confidence]

        return AppleAnalysisResult(
            source_type=source_type,
            findings=findings,
            raw_preview=raw_preview,
            file_name=filename,
            total_lines=total_lines,
            is_panic_log=True,
            device_info=device_info,
        )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9 — LIBMOBILEDEVICE PANIC PULL
# ═══════════════════════════════════════════════════════════════════════════

def pull_panic_full(udid: str, dest_dir: Path,
                    tools_dir: Path | None = None) -> list[Path]:
    """
    Pull panic-full logs from a connected iPhone/iPad.

    Delegates to apple_panic_pull.pull_panic_logs() when available
    (supports panic-full, panic-base, analytics, sysdiagnose).
    Falls back to direct idevicecrashreport invocation otherwise.

    Returns a list of pulled file paths, or [] on failure.
    """
    import shutil
    import subprocess
    import sys

    # Try enhanced pull module first
    try:
        from apple_panic_pull import pull_panic_logs, _collect_panic_files
        dest_dir.mkdir(parents=True, exist_ok=True)
        result = pull_panic_logs(udid=udid, dest_dir=dest_dir, tools_dir=tools_dir)
        if result.success:
            return result.files
        # Fall through to legacy
    except ImportError:
        pass

    IS_WIN = sys.platform == "win32"

    # Locate binary
    binary: Path | None = None
    if tools_dir:
        for candidate in [
            tools_dir / ("idevicecrashreport.exe" if IS_WIN else "idevicecrashreport"),
            tools_dir / "idevicecrashreport",
        ]:
            if candidate.is_file():
                binary = candidate
                break

    if binary is None:
        found = shutil.which("idevicecrashreport")
        if found:
            binary = Path(found)

    if binary is None:
        return []

    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(binary), "-u", udid, "--extract", str(dest_dir)]
    kwargs: dict = dict(capture_output=True, text=True, timeout=30,
                        encoding="utf-8", errors="replace")
    if IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    try:
        subprocess.run(cmd, **kwargs)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, UnicodeDecodeError):
        return []

    # Collect all pulled files (panic-full, ips, panic)
    return [
        p for p in dest_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".ips", ".panic", ".txt", ".log", ""}
    ]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10 — REPORT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
}
_SEV_COLOR = {
    Severity.CRITICAL: "#FF5555",
    Severity.HIGH:     "#FF8C00",
    Severity.MEDIUM:   "#FFD700",
    Severity.LOW:      "#87CEEB",
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


def format_markdown_report(result: AppleAnalysisResult) -> str:
    lines: list[str] = [
        "# Apple Panic Log Analysis Report",
        "",
        f"**File:** `{result.file_name}`  ",
        f"**Source type:** {result.source_type.value}  ",
        f"**Total lines:** {result.total_lines:,}  ",
        f"**Findings:** {len(result.findings)}",
        "",
    ]

    if result.device_info:
        lines.append("## Device Information\n")
        for k, v in result.device_info.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    if not result.is_panic_log:
        lines += [
            "## ⚠️ Not Recognised as Apple Panic Log",
            "",
            "This file does not contain recognisable Apple kernel panic signatures.",
            "Supported: panic-full, panic-base, .ips analytics, sysdiagnose archives.",
            "",
        ]
        return "\n".join(lines)

    if not result.findings:
        lines += [
            "## ✅ No Hardware Faults Detected",
            "",
            "No hardware fault signatures were found above the confidence threshold.",
            "This may be a software-only panic — update iOS or restore via DFU.",
            "",
        ]
        return "\n".join(lines)

    lines.append("## Findings\n")
    for i, f in enumerate(result.findings, 1):
        icon = _SEV_ICON.get(f.severity, "⚪")
        lines += [
            f"### {i}. {icon} [{f.category}] {f.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {f.severity.value.upper()} |",
            f"| **Confidence** | {f.confidence}% ({f.confidence_label}) |",
            f"| **Source** | {f.source_type.value} |",
            "",
            "#### Evidence",
            "",
            "```",
        ]
        for ev in f.evidence[:2]:
            lines.append(ev)
        lines += [
            "```",
            "",
            "#### Repair Suggestions",
            "",
        ]
        for s in f.suggestions:
            lines.append(f"- {s}")
        lines.append("")

    return "\n".join(lines)


def _html_esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def format_html_report(result: AppleAnalysisResult) -> str:
    """Generate a self-contained dark-themed HTML report."""
    sev_color = {s.value: c for s, c in _SEV_COLOR.items()}

    heading = _html_esc(result.file_name)
    css = """
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#1E1E2E;color:#CDD6F4;margin:0;padding:24px;}
    h1{color:#CBA6F7;font-size:22px;margin-bottom:4px;}
    h2{color:#89B4FA;font-size:16px;border-bottom:1px solid #313244;padding-bottom:6px;}
    h3{font-size:14px;margin:8px 0 4px;}
    .meta{color:#6C7086;font-size:12px;margin-bottom:16px;}
    .card{background:#181825;border:1px solid #313244;border-radius:8px;
          padding:16px;margin-bottom:12px;}
    .chip{display:inline-block;padding:3px 10px;border-radius:12px;
          font-size:11px;font-weight:600;margin-right:6px;}
    .ev{background:#11111B;border-radius:6px;padding:10px;
        font-family:'Fira Code',Consolas,monospace;font-size:11px;
        color:#A6E3A1;white-space:pre-wrap;word-break:break-all;
        max-height:160px;overflow-y:auto;}
    .sug{color:#CDD6F4;font-size:12px;margin:3px 0;}
    .sug-num{font-weight:700;margin-right:6px;}
    .devinfo{background:#181825;border:1px solid #313244;border-radius:8px;
             padding:12px 16px;margin-bottom:16px;font-size:12px;}
    .devinfo span{color:#6C7086;margin-right:8px;}
    """

    parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
             f"<title>PanicLab — {heading}</title>"
             f"<style>{css}</style></head><body>",
             f"<h1>🍎 Apple Panic Log Report</h1>",
             f"<div class='meta'>File: <b>{_html_esc(result.file_name)}</b> &nbsp;·&nbsp; "
             f"Source: <b>{result.source_type.value}</b> &nbsp;·&nbsp; "
             f"Lines: <b>{result.total_lines:,}</b> &nbsp;·&nbsp; "
             f"Findings: <b>{len(result.findings)}</b></div>"]

    if result.device_info:
        parts.append("<div class='devinfo'>")
        for k, v in result.device_info.items():
            parts.append(f"<span>{_html_esc(k)}:</span><b>{_html_esc(v)}</b> &nbsp;")
        parts.append("</div>")

    if not result.is_panic_log:
        parts.append("<h2>⚠️ Not Recognised as Apple Panic Log</h2>"
                     "<p style='color:#6C7086;'>Supported: panic-full, panic-base, "
                     ".ips analytics, sysdiagnose archives.</p>")
        parts.append("</body></html>")
        return "".join(parts)

    if not result.findings:
        parts.append("<h2>✅ No Hardware Faults Detected</h2>"
                     "<p style='color:#50FA7B;'>No hardware fault signatures found above "
                     "the confidence threshold. Consider a DFU restore for software-only panics.</p>")
        parts.append("</body></html>")
        return "".join(parts)

    parts.append("<h2>Findings</h2>")
    for i, f in enumerate(result.findings, 1):
        sc  = sev_color.get(f.severity.value, "#6C7086")
        cc  = _CAT_COLOR.get(f.category, "#6C7086")
        icon = _SEV_ICON.get(f.severity, "⚪")
        parts.append(f"<div class='card'>")
        parts.append(f"<h3>{i}. {icon} {_html_esc(f.title)}</h3>")
        parts.append(
            f"<span class='chip' style='background:{sc}22;color:{sc};'>"
            f"{f.severity.value.upper()}</span>"
            f"<span class='chip' style='background:{cc}22;color:{cc};'>"
            f"{_html_esc(f.category.value)}</span>"
            f"<span class='chip' style='background:#313244;color:#A6ADC8;'>"
            f"Confidence: {f.confidence}% ({_html_esc(f.confidence_label)})</span>"
            f"<span class='chip' style='background:#252535;color:#6C7086;'>"
            f"{_html_esc(f.source_type.value)}</span>"
        )
        if f.evidence:
            ev_text = _html_esc("\n".join(f.evidence[:2]))
            parts.append(f"<p style='color:#6C7086;font-size:11px;margin:10px 0 4px;font-weight:600;'>EVIDENCE</p>")
            parts.append(f"<div class='ev'>{ev_text}</div>")
        if f.suggestions:
            parts.append(f"<p style='color:#6C7086;font-size:11px;margin:10px 0 4px;font-weight:600;'>REPAIR SUGGESTIONS</p>")
            for j, sug in enumerate(f.suggestions, 1):
                parts.append(
                    f"<div class='sug'><span class='sug-num' style='color:{sc};'>{j}.</span>"
                    f"{_html_esc(sug)}</div>"
                )
        parts.append("</div>")

    parts.append("</body></html>")
    return "".join(parts)
