"""
android_analyzer.py — PanicLab Android Kernel Crash Analyzer
=============================================================
Supports:  tombstone, dumpstate, ramoops, pstore, last_kmsg
Ignores:   app-level crashes (Java/Kotlin exceptions, ANRs)
Detects:   UFS/eMMC, RAM, PMIC, Thermal, CPU/GPU, Modem faults

Output per finding:
  - category    : str   (UFS, RAM, PMIC, Thermal, CPU_GPU, Modem, Kernel)
  - title       : str
  - severity    : critical | high | medium | low
  - confidence  : 0-100
  - evidence    : list[str]  (raw snippets with context)
  - suggestions : list[str]  (actionable repair steps)
  - source_type : str   (tombstone | dumpstate | ramoops | pstore | last_kmsg | unknown)
"""

from __future__ import annotations

import re
import zipfile
import io
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


class Category(StrEnum):
    UFS_EMMC = "UFS/eMMC"
    RAM      = "RAM"
    PMIC     = "PMIC"
    THERMAL  = "Thermal"
    CPU_GPU  = "CPU/GPU"
    MODEM    = "Modem"
    KERNEL   = "Kernel"
    WATCHDOG = "Watchdog"
    UNKNOWN  = "Unknown"


class SourceType(StrEnum):
    TOMBSTONE = "tombstone"
    DUMPSTATE = "dumpstate"
    RAMOOPS   = "ramoops"
    PSTORE    = "pstore"
    LAST_KMSG = "last_kmsg"
    UNKNOWN   = "unknown"


@dataclass
class Finding:
    category:    Category
    title:       str
    severity:    Severity
    confidence:  int          # 0-100
    evidence:    list[str]    = field(default_factory=list)
    suggestions: list[str]    = field(default_factory=list)
    source_type: SourceType   = SourceType.UNKNOWN
    line_refs:   list[int]    = field(default_factory=list)

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 85: return "Very High"
        if self.confidence >= 70: return "High"
        if self.confidence >= 50: return "Medium"
        if self.confidence >= 30: return "Low"
        return "Very Low"


@dataclass
class AnalysisResult:
    source_type:  SourceType
    findings:     list[Finding]
    raw_preview:  str          # first ~100 lines for display
    file_name:    str
    total_lines:  int
    is_kernel_log: bool        # False → probably an app crash; skip


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — SOURCE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

_TOMBSTONE_MARKERS = re.compile(
    r"(Build fingerprint:|Abort message:|signal \d+ \(SIG|"
    r"backtrace:|#\d{2}\s+pc\s+[0-9a-fA-F]+|"
    r"tombstone_\d+|Cmdline:.*zygote)", re.I
)
_RAMOOPS_MARKERS = re.compile(
    r"(Oops:|BUG:|Call Trace:|RIP:|PC is at|"
    r"\[\s*\d+\.\d+\]\s+Kernel panic|pstore/ram)", re.I
)
_DUMPSTATE_MARKERS = re.compile(
    r"(------ DUMPSYS|------ KERNEL LOG|dumpstate:|"
    r"== dumpstate|DUMPSYS MEMINFO)", re.I
)
_PSTORE_MARKERS  = re.compile(r"(pstore:|/dev/pstore|console-ramoops)", re.I)
_LAST_KMSG_MARKERS = re.compile(
    r"(last_kmsg|<\d>\[\s*\d+\.\d+\]|Kernel panic.*not syncing|"
    r"\[\s*\d+\.\d+\]\s+\w+:)", re.I
)

# App-level crash indicators → if these dominate, skip analysis
_APP_CRASH_MARKERS = re.compile(
    r"(java\.lang\.|android\.app\.ActivityManager|"
    r"FATAL EXCEPTION|AndroidRuntime|at com\.|at android\.|"
    r"dalvik\.|art\.|\bANR\b.*in\s+\S+\.\S+)", re.I
)
_KERNEL_INDICATORS = re.compile(
    r"(<\d>|\[\s*\d+\.\d+\]|Kernel panic|Oops:|BUG:|"
    r"kernel BUG|Unable to handle|PC is at|Call Trace:|"
    r"signal \d+ \(SIG|tombstone|ramoops|pstore)", re.I
)


def classify_source(text: str) -> tuple[SourceType, bool]:
    """
    Returns (SourceType, is_kernel_log).
    is_kernel_log=False means it's predominantly an app crash → skip.
    """
    kernel_hits = len(_KERNEL_INDICATORS.findall(text[:8000]))
    app_hits    = len(_APP_CRASH_MARKERS.findall(text[:8000]))

    # Predominantly app crash
    if app_hits > 10 and kernel_hits < 3:
        return SourceType.UNKNOWN, False

    if _PSTORE_MARKERS.search(text[:2000]):
        return SourceType.PSTORE, True
    if _RAMOOPS_MARKERS.search(text[:4000]):
        return SourceType.RAMOOPS, True
    if _DUMPSTATE_MARKERS.search(text[:4000]):
        return SourceType.DUMPSTATE, True
    if _TOMBSTONE_MARKERS.search(text[:4000]):
        return SourceType.TOMBSTONE, True
    if _LAST_KMSG_MARKERS.search(text[:4000]):
        return SourceType.LAST_KMSG, True

    if kernel_hits >= 2:
        return SourceType.LAST_KMSG, True

    return SourceType.UNKNOWN, kernel_hits > 0


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — PATTERN LIBRARY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Pattern:
    regex:       re.Pattern
    category:    Category
    title:       str
    severity:    Severity
    confidence:  int
    suggestions: list[str]


def _p(pattern: str, cat: Category, title: str, sev: Severity,
       conf: int, suggestions: list[str]) -> Pattern:
    return Pattern(re.compile(pattern, re.I | re.M), cat, title, sev, conf, suggestions)


PATTERNS: list[Pattern] = [

    # ── UFS / eMMC ────────────────────────────────────────────────────────
    _p(r"UFS.*error|ufshcd.*error|ufshcd.*failed|ufs.*timeout",
       Category.UFS_EMMC, "UFS Controller Error", Severity.CRITICAL, 90,
       ["Replace UFS storage chip (BGA reball/reflow or full IC swap)",
        "Check UFS power rails — VCCQ/VCCQ2 must be stable (measure with multimeter)",
        "Inspect UFS clock lanes for shorts on signal layer",
        "Re-flash firmware partition if error is limited to config descriptor"]),

    _p(r"mmc\d+:.*error|mmc.*cmd\d+.*timeout|mmc.*data\s+timeout|"
       r"blk_update_request.*I/O error|end_request.*I/O error",
       Category.UFS_EMMC, "eMMC I/O Error", Severity.CRITICAL, 88,
       ["Reflow eMMC BGA — cold-joint failure is the most common root cause",
        "Measure VCCQ (1.8V) and VCC (3.3V) under load; drooping >50mV indicates power rail fault",
        "Check CMD/CLK/DAT lines with oscilloscope for signal integrity",
        "If reflow fails, replace eMMC chip with matching part number and flash firmware"]),

    _p(r"ufshcd.*fatal|ufshcd.*link startup failed|ufs.*hw reset",
       Category.UFS_EMMC, "UFS Fatal / Link Failure", Severity.CRITICAL, 92,
       ["UFS link startup failure usually indicates power sequencing fault or dead UFS IC",
        "Measure VCC (2.7-3.6V) and VCCQ (1.2V) at UFS pads",
        "Inspect power regulators feeding UFS — replace if shorted or out-of-spec",
        "Replace UFS IC if power rails are healthy but link does not establish"]),

    _p(r"f2fs.*panic|ext4.*panic|filesystem.*error.*panic|jbd2.*aborted",
       Category.UFS_EMMC, "Filesystem Corruption Panic", Severity.HIGH, 80,
       ["Filesystem journal abort typically follows an earlier storage I/O error",
        "Boot to recovery and run e2fsck/f2fs_fsck",
        "If bad blocks are found, storage IC is failing — plan replacement",
        "Recover data first; bad-block maps grow over time"]),

    _p(r"squashfs.*error|ubifs.*error|mtd.*error|nand.*error|"
       r"nand.*uncorrectable",
       Category.UFS_EMMC, "NAND/Flash Storage Error", Severity.HIGH, 82,
       ["NAND wear or partial failure detected",
        "Dump partition map and identify which partition is affected",
        "Re-flash affected partition if firmware corruption; replace chip if HW failure"]),

    # ── RAM / Memory ──────────────────────────────────────────────────────
    _p(r"Unable to handle kernel paging request|"
       r"BUG:.*NULL pointer dereference|"
       r"general protection fault|page fault",
       Category.RAM, "Kernel Page Fault / NULL Deref", Severity.CRITICAL, 85,
       ["Page faults at fixed addresses (0x00000000–0x0000ffff) are NULL deref — likely kernel bug",
        "Random high addresses indicate RAM hardware fault — run extended memtest",
        "Check RAM power rail (VDDQ) for noise or drooping",
        "If fault address changes across reboots, suspect bad LPDDR solder joint (reflow RAM)"]),

    _p(r"Oops:.*\[#\d+\]|kernel BUG at|BUG:.*kernel NULL|"
       r"RIP:.*\+0x|PC is at \w+\+0x",
       Category.RAM, "Kernel Oops / BUG", Severity.CRITICAL, 87,
       ["Capture the full Oops including registers, backtrace, and module list",
        "Decode with addr2line against the kernel vmlinux for exact source location",
        "Persistent Oops at the same address = software bug; random = hardware fault",
        "If hardware: reflow LPDDR BGA; replace RAM IC if reflow fails"]),

    _p(r"memory corruption|KASAN:.*out-of-bounds|KASAN:.*use-after-free|"
       r"SLUB:.*corruption|slab.*corruption",
       Category.RAM, "Memory Corruption (KASAN/SLUB)", Severity.CRITICAL, 88,
       ["KASAN reports indicate either a kernel driver bug or RAM hardware error",
        "If the corrupted address is consistent → kernel bug; report upstream",
        "If addresses are random → failing RAM — reflow LPDDR or replace",
        "Check for overclocked/undervolted RAM from previous repairs"]),

    _p(r"oom.?killer|Out of memory.*kill|lowmemorykiller.*kswapd",
       Category.RAM, "OOM Killer Activated", Severity.MEDIUM, 70,
       ["OOM killer itself is not a hardware fault — verify RAM capacity via /proc/meminfo",
        "Persistent OOM on a device with adequate RAM may indicate RAM failing (reduced effective capacity)",
        "Run memtester or a stress test to confirm RAM integrity",
        "If confirmed hardware: replace LPDDR package"]),

    _p(r"ECC.*error|DRAM.*error|memory.*single.?bit.*error|"
       r"memory.*double.?bit.*error|EDAC.*error",
       Category.RAM, "DRAM ECC Error", Severity.CRITICAL, 95,
       ["ECC errors are a direct hardware signal of DRAM bit failure",
        "Single-bit errors: may be corrected but indicate degrading RAM",
        "Double-bit (uncorrectable): immediate LPDDR replacement required",
        "Inspect RAM for physical damage, corrosion, or BGA cold joints"]),

    # ── PMIC / Power ──────────────────────────────────────────────────────
    _p(r"PMIC.*error|pmic.*fault|pm\d+.*error|regulator.*failed|"
       r"vreg.*failed|rpm.*error",
       Category.PMIC, "PMIC / Regulator Fault", Severity.CRITICAL, 88,
       ["PMIC fault typically means a shorted load or failed regulator output",
        "Measure all regulated rails (VDD_CPU, VDD_GPU, VDDQ_RAM, etc.) under load",
        "Isolate shorted rail by removing loads one at a time",
        "Replace PMIC IC if rail output is wrong with no short on the load side"]),

    _p(r"power.*rail.*collapse|voltage.*collapse|brown.?out|"
       r"undervolted|supply.*unstable",
       Category.PMIC, "Power Rail Collapse / Brownout", Severity.CRITICAL, 85,
       ["Voltage collapse during load spike — check battery ESR and charging IC",
        "Measure CPU/GPU supply with oscilloscope during load — look for >100mV droop",
        "Inspect battery connector for oxidation; replace battery if ESR >200mΩ",
        "Check bulk capacitors on main power rails for ESR degradation"]),

    _p(r"charger.*fault|charging.*error|BQ\d+.*fault|"
       r"battery.*overvoltage|battery.*undervoltage",
       Category.PMIC, "Charging IC / Battery Fault", Severity.HIGH, 80,
       ["Charging IC fault — check VBUS input (5V), battery voltage (3.0-4.35V)",
        "Inspect charging IC (e.g., BQ25xxx) for heat damage or shorted FETs",
        "Measure battery voltage directly — below 3.0V may require activation charge",
        "Replace charging IC if FET resistance is out of spec"]),

    _p(r"pmic.*shutdown|PMIC.*UVLO|power.*off.*unexpect|"
       r"sudden.*power.*loss",
       Category.PMIC, "Unexpected PMIC Shutdown (UVLO)", Severity.HIGH, 83,
       ["Under-voltage lockout — battery cannot sustain load",
        "Replace battery; measure capacity and ESR",
        "If battery is new: inspect for shorted power domain pulling down supply",
        "Check main power FET (load switch) — shorted FET can cause UVLO"]),

    # ── Thermal ───────────────────────────────────────────────────────────
    _p(r"thermal.*shutdown|thermal.*emergency|thermald.*critical|"
       r"thermal.*critical|critical.*temperature|temperature.*critical|"
       r"cpu.*overtemp|gpu.*overtemp|junction.*temperature|"
       r"thermal.*shutting|temp.*exceeded|overheat.*detected",
       Category.THERMAL, "Thermal Shutdown / Overtemp", Severity.CRITICAL, 90,
       ["Device exceeded thermal limits — find heat source with thermal camera",
        "Remove and inspect thermal paste/pad on SoC heatspreader",
        "Check for blocked vents or missing graphite spreader",
        "If no load-dependent: thermal sensor may be reporting falsely — check sensor resistance"]),

    _p(r"tsens.*fault|temperature.*sensor.*error|thermal.*zone.*error",
       Category.THERMAL, "Thermal Sensor Fault", Severity.HIGH, 78,
       ["Thermal sensor read error — device may shut down incorrectly",
        "Check TSENS power supply and I2C/SPI bus integrity",
        "A stuck high reading causes unnecessary throttling; stuck low = no protection",
        "Replace SoC if thermal sensors are internal and showing consistent errors"]),

    _p(r"cpu.*throttl|gpu.*throttl|thermal.*throttl",
       Category.THERMAL, "Thermal Throttling Detected", Severity.MEDIUM, 65,
       ["Heavy throttling may indicate blocked airflow or degraded TIM",
        "Re-apply thermal paste on CPU/GPU; replace thermal pad if compressed",
        "Inspect for dust accumulation in cooling assembly"]),

    # ── CPU / GPU ─────────────────────────────────────────────────────────
    _p(r"cpu.*hang|cpu.*stuck|cpu.*lockup|hard lockup|soft lockup",
       Category.CPU_GPU, "CPU Lockup / Hang", Severity.CRITICAL, 88,
       ["Hard lockup = CPU not responding to NMI — usually hardware fault or deadlock",
        "Check CPU supply voltage stability under load",
        "Soft lockup is often a software deadlock — note which CPU and process",
        "If lockup is reproducible under load: reflow SoC BGA or replace"]),

    _p(r"kgsl.*fault|gpu.*fault|gpu.*hang|adreno.*hang|"
       r"mali.*fault|powervr.*fault|gpu.*reset",
       Category.CPU_GPU, "GPU Fault / Hang", Severity.HIGH, 85,
       ["GPU hang/fault — check GPU power rail (VDD_GPU)",
        "GPU memory errors often cause hangs — inspect LPDDR channels",
        "Driver-level reset may recover; persistent hangs indicate HW fault",
        "Reflow SoC (GPU is integrated) or replace SoC if fault is persistent"]),

    _p(r"soc.*temperature|junction.*overheat|cpu\d+.*offline|"
       r"core.*offline.*thermal",
       Category.CPU_GPU, "CPU Core Offline (Thermal/Fault)", Severity.HIGH, 75,
       ["Core taken offline due to thermal limit or hardware fault",
        "Distinguish thermal vs. fault: check temperature logs at time of offline event",
        "Persistent core offline = failing CPU core — SoC replacement required",
        "Thermal cause: improve cooling; apply new TIM"]),

    _p(r"panic.*SError|panic.*L2 cache|cache.*parity.*error|"
       r"L1.*error|L2.*error",
       Category.CPU_GPU, "Cache / SError Fault", Severity.CRITICAL, 90,
       ["ARM SError or cache parity error — hardware-level CPU fault",
        "SError is typically caused by memory subsystem failure (RAM or bus)",
        "Reflow SoC BGA; if fault persists, replace SoC",
        "Verify no voltage noise on CPU core supply"]),

    _p(r"watchdog.*bark|watchdog.*bite|wdog.*reset|"
       r"apps_wdog_bite|blsp.*hang",
       Category.WATCHDOG, "Watchdog Bark/Bite Reset", Severity.HIGH, 85,
       ["Watchdog bite means a subsystem stopped feeding the watchdog — investigate which one",
        "APPS watchdog: CPU was stuck — check for deadlock in kernel threads",
        "BLSP/peripheral hang: check connected peripheral (UART, SPI, I2C device)",
        "Subsystem restart logs ('SSR') nearby in log will name the offending component"]),

    # ── Modem ─────────────────────────────────────────────────────────────
    _p(r"modem.*crash|mpss.*crash|subsys.*mpss|ssr.*modem|"
       r"modem.*fatal|q6.*crash",
       Category.MODEM, "Modem (MPSS) Crash", Severity.HIGH, 87,
       ["Modem subsystem crash — check for RF hardware damage (antenna, PA, front-end module)",
        "Inspect modem power rails (VDD_MSS, VDD_Q6)",
        "A modem crash after physical drop usually indicates antenna connector failure",
        "Update modem firmware (MPSS partition) if crash is firmware-related",
        "Persistent modem crash on a specific carrier may be a baseband firmware bug"]),

    _p(r"ADSP.*crash|aDSP.*fatal|adsp.*restart|subsys.*adsp",
       Category.MODEM, "ADSP Crash", Severity.HIGH, 80,
       ["Audio DSP crash — check microphone and audio codec hardware",
        "Inspect ADSP power rail; look for shorted audio amp",
        "If crash correlates with audio calls: likely codec or I2S bus fault",
        "Update DSP firmware if available"]),

    _p(r"wcnss.*crash|wlan.*firmware.*crash|subsys.*wcnss|"
       r"cnss.*firmware",
       Category.MODEM, "WLAN/BT Firmware Crash (WCNSS)", Severity.MEDIUM, 78,
       ["Wi-Fi/BT co-processor crash — often firmware bug or power issue",
        "Check WLAN power rail and antenna connection",
        "Update WCNSS firmware partition",
        "If crash is antenna-related: reseat or replace antenna connector"]),

    _p(r"ipa.*fatal|rmnet.*fatal|data.*subsystem.*crash",
       Category.MODEM, "Data Subsystem (IPA/rmnet) Crash", Severity.MEDIUM, 72,
       ["Data path crash — may follow modem crash or be independent",
        "Check for firmware update addressing IPA driver issues",
        "Inspect USB/PCIe modem connection if external modem"]),

    # ── Generic Kernel Panic ──────────────────────────────────────────────
    _p(r"Kernel panic.*not syncing|kernel panic",
       Category.KERNEL, "Kernel Panic", Severity.CRITICAL, 80,
       ["Capture the panic reason line and full Call Trace",
        "Decode backtrace with addr2line to identify exact failing function",
        "Check if panic is reproducible — random panics suggest hardware fault",
        "Consistent panic at same location = kernel/driver bug"]),

    _p(r"RCU.*stall|rcu_sched.*detected stall|RCU.*timeout",
       Category.KERNEL, "RCU Stall", Severity.HIGH, 75,
       ["RCU stall: a CPU is stuck in a long non-preemptible section",
        "Look for deadlocked spinlock or interrupt storm in the log",
        "May indicate CPU hardware fault — run CPU stress test",
        "Check interrupt latency; a stuck peripheral can cause RCU stalls"]),

    _p(r"spinlock.*timeout|mutex.*deadlock|deadlock.*detected",
       Category.KERNEL, "Deadlock Detected", Severity.HIGH, 72,
       ["Kernel deadlock — identify the two lock holders from the backtrace",
        "Usually a kernel/driver bug — file bug with full log",
        "Workaround: update kernel/firmware if patch available"]),
]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — CONTEXT EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

def _extract_context(lines: list[str], match_line: int,
                     context: int = 5) -> list[str]:
    start = max(0, match_line - context)
    end   = min(len(lines), match_line + context + 1)
    result = []
    for i in range(start, end):
        prefix = ">>> " if i == match_line else "    "
        result.append(f"[L{i+1:>5}] {prefix}{lines[i].rstrip()}")
    return result


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — DEDUPLICATOR & MERGER
# ═══════════════════════════════════════════════════════════════════════════

def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings of the same (category, title) — combine evidence,
    take the max confidence, keep the highest severity.
    """
    merged: dict[tuple[Category, str], Finding] = {}
    for f in findings:
        key = (f.category, f.title)
        if key not in merged:
            merged[key] = Finding(
                category=f.category,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                evidence=list(f.evidence),
                suggestions=list(f.suggestions),
                source_type=f.source_type,
                line_refs=list(f.line_refs),
            )
        else:
            existing = merged[key]
            # Keep highest severity
            sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            if sev_order.index(f.severity) < sev_order.index(existing.severity):
                existing.severity = f.severity
            existing.confidence = min(100, max(existing.confidence, f.confidence))
            # Keep up to 3 evidence blocks
            existing.evidence.extend(e for e in f.evidence if e not in existing.evidence)
            existing.evidence = existing.evidence[:3]
            existing.line_refs.extend(f.line_refs)

    # Sort: critical first, then by confidence desc
    sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                Severity.MEDIUM: 2, Severity.LOW: 3}
    return sorted(merged.values(),
                  key=lambda x: (sev_rank[x.severity], -x.confidence))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — APP CRASH FILTER
# ═══════════════════════════════════════════════════════════════════════════

_JAVA_EXCEPTION = re.compile(
    r"^(\s*at\s+\w[\w.$]+\.\w+\(|"
    r"\s*java\.\w|"
    r"\s*android\.\w|"
    r"FATAL EXCEPTION|"
    r"Process:.*PID:\s*\d)", re.M
)

def _is_app_crash_block(block: str) -> bool:
    """Return True if this text block is primarily a Java/app crash."""
    java_hits   = len(_JAVA_EXCEPTION.findall(block))
    kernel_hits = len(_KERNEL_INDICATORS.findall(block))
    return java_hits > 5 and kernel_hits < 2


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class AndroidCrashAnalyzer:

    def __init__(self, context_lines: int = 5, min_confidence: int = 40):
        self.context_lines  = context_lines
        self.min_confidence = min_confidence

    # ── Public entry points ───────────────────────────────────────────────

    def analyze_file(self, path: Path) -> AnalysisResult:
        """Analyze a single file (plain text or zip/gz)."""
        text, fname = self._read_file(path)
        return self._analyze_text(text, fname)

    def analyze_text(self, text: str, filename: str = "input") -> AnalysisResult:
        return self._analyze_text(text, filename)

    # ── Internal ─────────────────────────────────────────────────────────

    def _read_file(self, path: Path) -> tuple[str, str]:
        suffix = path.suffix.lower()

        if suffix == ".zip":
            return self._read_zip(path), path.name
        if suffix == ".gz":
            import gzip
            with gzip.open(path, "rt", errors="replace") as f:
                return f.read(), path.name
        # Plain text (tombstone, log, etc.)
        return path.read_text(encoding="utf-8", errors="replace"), path.name

    def _read_zip(self, path: Path) -> str:
        """
        Extract from a bugreport ZIP. Priority:
          1. last_kmsg / console-ramoops / pstore files
          2. dmesg / kernel log
          3. tombstones
          4. main bugreport text
        """
        collected: list[str] = []
        priorities = [
            "last_kmsg", "console-ramoops", "pstore",
            "dmesg", "kernel", "tombstone",
        ]
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            # Sort by priority
            def _rank(n: str) -> int:
                nl = n.lower()
                for i, kw in enumerate(priorities):
                    if kw in nl:
                        return i
                return len(priorities)
            for name in sorted(names, key=_rank):
                if any(kw in name.lower() for kw in priorities):
                    try:
                        data = zf.read(name).decode("utf-8", errors="replace")
                        collected.append(f"=== FILE: {name} ===\n{data}")
                        if len("\n".join(collected)) > 500_000:
                            break
                    except Exception:
                        continue
            # Fallback: read the first large text file
            if not collected:
                for name in names:
                    info = zf.getinfo(name)
                    if info.file_size > 1000:
                        try:
                            data = zf.read(name).decode("utf-8", errors="replace")
                            collected.append(data)
                            if len(data) > 200_000:
                                break
                        except Exception:
                            continue
        return "\n".join(collected)

    def _analyze_text(self, text: str, filename: str) -> AnalysisResult:
        source_type, is_kernel = classify_source(text)

        lines        = text.splitlines()
        total_lines  = len(lines)
        raw_preview  = "\n".join(lines[:100])

        if not is_kernel:
            return AnalysisResult(
                source_type=source_type,
                findings=[],
                raw_preview=raw_preview,
                file_name=filename,
                total_lines=total_lines,
                is_kernel_log=False,
            )

        findings: list[Finding] = []

        for pat in PATTERNS:
            for match_obj in pat.regex.finditer(text):
                # Find which line number this is
                match_start = match_obj.start()
                line_no     = text[:match_start].count("\n")

                # Skip if this is inside an app-crash block
                block_start = max(0, match_start - 500)
                block_end   = min(len(text), match_start + 500)
                if _is_app_crash_block(text[block_start:block_end]):
                    continue

                evidence = _extract_context(lines, line_no, self.context_lines)
                finding  = Finding(
                    category=pat.category,
                    title=pat.title,
                    severity=pat.severity,
                    confidence=pat.confidence,
                    evidence=evidence,
                    suggestions=list(pat.suggestions),
                    source_type=source_type,
                    line_refs=[line_no + 1],
                )
                findings.append(finding)

        # Merge duplicates, filter low-confidence
        findings = _merge_findings(findings)
        findings = [f for f in findings if f.confidence >= self.min_confidence]

        return AnalysisResult(
            source_type=source_type,
            findings=findings,
            raw_preview=raw_preview,
            file_name=filename,
            total_lines=total_lines,
            is_kernel_log=True,
        )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 — CLI REPORT FORMATTER (used by both CLI and UI export)
# ═══════════════════════════════════════════════════════════════════════════

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
}


def format_markdown_report(result: AnalysisResult) -> str:
    lines: list[str] = [
        f"# Android Kernel Crash Analysis Report",
        f"",
        f"**File:** `{result.file_name}`  ",
        f"**Source type:** {result.source_type.value}  ",
        f"**Total lines:** {result.total_lines:,}  ",
        f"**Findings:** {len(result.findings)}",
        f"",
    ]

    if not result.is_kernel_log:
        lines += [
            "## ⚠️ Not a Kernel Log",
            "",
            "This file appears to be an **application-level crash** (Java/Kotlin exception, ANR).",
            "PanicLab's Android analyzer focuses on kernel / hardware faults.",
            "Use the tombstone or logcat output instead.",
            "",
        ]
        return "\n".join(lines)

    if not result.findings:
        lines += [
            "## ✅ No Hardware Faults Detected",
            "",
            "No kernel-level hardware fault signatures were found above the",
            f"configured confidence threshold.",
            "",
        ]
        return "\n".join(lines)

    lines.append("## Findings\n")

    for i, f in enumerate(result.findings, 1):
        icon = _SEV_ICON.get(f.severity, "⚪")
        lines += [
            f"### {i}. {icon} [{f.category}] {f.title}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {f.severity.value.upper()} |",
            f"| **Confidence** | {f.confidence}% ({f.confidence_label}) |",
            f"| **Source** | {f.source_type.value} |",
            f"",
            f"#### Evidence",
            f"",
            f"```",
        ]
        for ev in f.evidence[:2]:
            lines.append(ev)
        lines += [
            f"```",
            f"",
            f"#### Repair Suggestions",
            f"",
        ]
        for s in f.suggestions:
            lines.append(f"- {s}")
        lines.append("")

    return "\n".join(lines)


def format_html_report(result: AnalysisResult) -> str:
    """Generate a self-contained HTML report."""
    sev_color = {
        "critical": "#FF5555",
        "high":     "#FF8C00",
        "medium":   "#FFD700",
        "low":      "#87CEEB",
    }

    cards = ""
    for f in result.findings:
        color   = sev_color.get(f.severity.value, "#888")
        ev_html = "\n".join(
            f'<div class="ev-line">{_html_esc(e)}</div>' for e in f.evidence[:2]
        )
        sug_html = "\n".join(
            f'<li>{_html_esc(s)}</li>' for s in f.suggestions
        )
        cards += f"""
<div class="card" style="border-left:4px solid {color}">
  <div class="card-header">
    <span class="cat">{_html_esc(f.category.value)}</span>
    <span class="title">{_html_esc(f.title)}</span>
    <span class="sev" style="color:{color}">{f.severity.value.upper()}</span>
    <span class="conf">{f.confidence}% confidence</span>
  </div>
  <details>
    <summary>Evidence</summary>
    <pre class="evidence">{ev_html}</pre>
  </details>
  <details open>
    <summary>Repair Suggestions</summary>
    <ul class="suggestions">{sug_html}</ul>
  </details>
</div>"""

    status = "app-crash" if not result.is_kernel_log else (
        "no-findings" if not result.findings else "has-findings"
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>PanicLab — Android Crash Report</title>
<style>
body{{font-family:monospace;background:#1E1E2E;color:#CDD6F4;padding:24px;margin:0}}
h1{{color:#CBA6F7;font-size:1.4em}}
.meta{{color:#6C7086;font-size:.85em;margin-bottom:24px}}
.card{{background:#181825;border-radius:8px;padding:16px;margin-bottom:16px}}
.card-header{{display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap}}
.cat{{background:#313244;color:#CBA6F7;padding:2px 8px;border-radius:4px;font-size:.8em}}
.title{{font-weight:600;font-size:1em;flex:1}}
.sev{{font-size:.8em;font-weight:700}}
.conf{{color:#6C7086;font-size:.8em}}
pre.evidence{{background:#11111B;padding:12px;border-radius:6px;overflow-x:auto;font-size:.78em;color:#A6E3A1}}
ul.suggestions{{margin:8px 0;padding-left:20px;color:#CDD6F4;font-size:.88em}}
ul.suggestions li{{margin:4px 0}}
details summary{{cursor:pointer;color:#6C7086;font-size:.85em;margin:4px 0}}
.ev-line{{line-height:1.5}}
</style></head><body>
<h1>🤖 Android Kernel Crash Report</h1>
<div class="meta">
  File: <b>{_html_esc(result.file_name)}</b> &nbsp;|&nbsp;
  Source: <b>{result.source_type.value}</b> &nbsp;|&nbsp;
  Lines: <b>{result.total_lines:,}</b> &nbsp;|&nbsp;
  Findings: <b>{len(result.findings)}</b>
</div>
{cards if status == "has-findings" else _status_banner(status)}
</body></html>"""


def _html_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _status_banner(status: str) -> str:
    if status == "app-crash":
        return ("<div style='color:#FFD700;padding:24px;background:#181825;"
                "border-radius:8px'>⚠️ This appears to be an app-level crash "
                "(Java/ANR). Android analyzer skipped.</div>")
    return ("<div style='color:#50FA7B;padding:24px;background:#181825;"
            "border-radius:8px'>✅ No kernel hardware fault signatures detected.</div>")
