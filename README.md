# PanicLab

**A desktop crash-log analyzer for iPhone panics and Android kernel crashes — with live device pulling, hardware-fault detection, and repair-ready reports.**

PanicLab is a PyQt6 desktop application built for repair technicians, support engineers, and power users who need to go from *"the phone keeps crashing"* to a confident hardware diagnosis without manually grepping through panic logs. Drop in a log file (or pull straight from a connected device) and PanicLab tells you what failed, how confident it is, and what to do about it.

---

## Table of Contents

- [Features](#features)
- [Screenshots / Pages](#screenshots--pages)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Option A: Standalone Windows executable (no Python required)](#option-a-standalone-windows-executable-no-python-required)
  - [Option B: Run from source](#option-b-run-from-source)
- [Bundling CLI Tools (adb / libimobiledevice)](#bundling-cli-tools-adb--libimobiledevice)
- [Running PanicLab](#running-paniclab)
- [Usage](#usage)
  - [Apple Analysis](#apple-analysis)
  - [Android Analysis](#android-analysis)
  - [Battery Health](#battery-health)
  - [Devices](#devices)
- [Supported Log Formats](#supported-log-formats)
- [What Gets Detected](#what-gets-detected)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Logging & Troubleshooting](#logging--troubleshooting)
- [Platform Notes](#platform-notes)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- 🍎 **iPhone/iPad panic log analysis** — parses `panic-full`, `panic-base` (base64/binary), analytics `.ips` JSON, and `sysdiagnose` bundles. Detects NAND/storage, battery/power, Face ID, display, charging, audio, and baseband faults.
- 🤖 **Android kernel crash analysis** — parses tombstones, dumpstate/bugreport ZIPs, ramoops/pstore, and `last_kmsg`. Detects UFS/eMMC, RAM, PMIC, thermal, CPU/GPU, modem, kernel, and watchdog faults.
- 🔋 **Android battery health** — live ADB polling or log-file parsing of `dumpsys battery`/`batterystats`, with manufacturer-aware parsing for Samsung (OneUI), Xiaomi (MIUI), OnePlus (OxygenOS), and Google Pixel (AOSP). Reports health %, cycle count, temperature, voltage, and capacity.
- 📲 **Direct device pulling** — no manual log exporting required:
  - **Apple:** pulls panic-full/panic-base/analytics logs straight off a connected, trusted iPhone/iPad via `idevicecrashreport` / `idevicediagnostics`.
  - **Android:** pulls tombstones, pstore/ramoops, or a live `logcat` dump over `adb`.
- 🧠 **Confidence-scored findings** — every detected issue includes a severity (critical/high/medium/low), a 0–100 confidence score, raw evidence with surrounding context, and actionable repair suggestions.
- 📋 **Exportable reports** — Markdown and HTML report generation per analysis.
- 🖱️ **Drag-and-drop everywhere** — drop `.ips`, `.panic`, `.txt`, `.log`, `.zip`, or `.gz` files anywhere in the window and PanicLab automatically routes them to the right page (it even sniffs ZIP/text contents to tell a crash bugreport apart from a battery dump).
- 🖥️ **Cross-platform** — runs on Windows, macOS, and Linux from the same codebase, with platform-specific device-discovery backends (no `pyimobiledevice` required, even on Windows).
- 📦 **Standalone Windows executable** — a self-contained `PanicLab.exe` build is available with the Python runtime, PyQt6, and the `adb`/libimobiledevice CLI tools all bundled in. No Python install, no `pip install`, no manually downloading tools — just run the `.exe`.
- 🎨 **Dark-themed native UI** — built on PyQt6, with a persistent config (theme, confidence thresholds, recent files, window geometry).

## Screenshots / Pages

PanicLab's sidebar has seven pages:

| Page | Description |
|---|---|
| 🏠 Dashboard | Overview cards (logs analysed, critical issues, devices tracked, reports generated) and recent activity. |
| 📱 Devices | Live list of connected Android/Apple devices, detected via ADB / libimobiledevice / WMI polling. |
| 🍎 Apple | Drop or pull iPhone/iPad panic logs; full finding breakdown with syntax-highlighted raw log viewer. |
| 🤖 Android | Drop or pull Android kernel crash logs/bugreports; same finding breakdown UI. |
| 🔋 Battery | Live or file-based Android battery health scoring. |
| 📋 Reports | Generated repair reports (Markdown/HTML export). |
| ⚙️ Settings | Theme, analysis confidence threshold, context lines, report format, battery module status. |

## Requirements

- **Python 3.11+** (the codebase uses `StrEnum` and PEP 604 `X | Y` type hints throughout)
- **PyQt6**
- **pydantic** (v2)
- **platformdirs**
- **pyqtdarktheme** (optional but recommended for theming)

Install everything with:

```bash
pip install PyQt6 pydantic platformdirs pyqtdarktheme
```

> There is currently no `requirements.txt`/`pyproject.toml` checked in — the line above is everything `main.py` imports at startup. Feel free to pin versions and freeze a `requirements.txt` for your environment.

### External CLI tools (optional, but required for live device pulling)

| Tool | Used for | Platform |
|---|---|---|
| `idevice_id`, `ideviceinfo`, `idevicecrashreport`, `idevicediagnostics` | Discovering and pulling logs from iPhone/iPad | macOS, Linux, Windows (bundled) |
| `adb` | Discovering and pulling logs from Android devices | macOS, Linux, Windows (bundled) |

These tools are **not required** to analyze log files you already have on disk — they're only needed for the "Pull from device" buttons. See the next section for how to make them available.

## Installation

There are two ways to get PanicLab running: grab the standalone executable (Windows, zero setup), or run it from source (any OS, requires Python).

### Option A: Standalone Windows executable (no Python required)

If you just want to use PanicLab and don't care about the source, download the latest `PanicLab.exe` from the project's Releases page and run it directly — that's it.

This build bundles **everything** into a single executable:
- The Python runtime and all dependencies (PyQt6, pydantic, platformdirs, pyqtdarktheme)
- `adb` (and its required Windows DLLs) for Android device communication
- `idevice_id.exe`, `ideviceinfo.exe`, `idevicecrashreport.exe`, and `idevicediagnostics.exe` for iPhone/iPad device communication

You do **not** need to install Python, run `pip install`, or manually populate a `tools/` folder — the [Requirements](#requirements) and [Bundling CLI Tools](#bundling-cli-tools-adb--libimobiledevice) sections below don't apply to this build.

The only external dependency that still applies is the one PanicLab can't bundle itself: **iTunes or the Apple Devices app** (Microsoft Store) must be installed so Windows has the *Apple Mobile Device USB Driver* available for talking to an iPhone/iPad over USB. Android pulling works out of the box with no extra installs (just enable **USB debugging** on the device).

> Building the executable yourself (e.g. via PyInstaller) isn't currently scripted in this repo — if you maintain a build spec for it, consider checking it in alongside a `tools/` directory pre-populated with the platform binaries above.

### Option B: Run from source

```bash
git clone <this-repo>
cd PanicLab
pip install PyQt6 pydantic platformdirs pyqtdarktheme
python main.py
```

This is the right option for macOS, Linux, or if you want to modify the code. See [Requirements](#requirements) and [Bundling CLI Tools](#bundling-cli-tools-adb--libimobiledevice) below for what you'll need to set up manually (the standalone `.exe` in Option A handles all of this for you).

## Bundling CLI Tools (adb / libimobiledevice)

> Using the standalone `PanicLab.exe` from [Option A](#option-a-standalone-windows-executable-no-python-required)? These tools are already bundled in — skip this section entirely.

PanicLab looks for CLI tools in this order:

1. **`tools/<name>`** (or **`tools/<name>.exe`** on Windows) — a folder named `tools/` placed directly next to `main.py`
2. **System `PATH`**

Expected layout:

```
PanicLab/
├── main.py
├── device_manager.py
├── apple_panic_pull.py
└── tools/
    ├── adb[.exe]                  # Android Debug Bridge
    ├── AdbWinApi.dll              # Windows-only, required alongside adb.exe
    ├── AdbWinUsbApi.dll           # Windows-only, required alongside adb.exe
    ├── idevice_id[.exe]           # libimobiledevice
    ├── ideviceinfo[.exe]
    ├── idevicecrashreport[.exe]
    └── idevicediagnostics[.exe]
```

**macOS**
```bash
brew install libimobiledevice
brew install android-platform-tools   # provides adb
idevicepair pair                      # trust the device once
```

**Linux**
```bash
sudo apt install libimobiledevice-utils adb     # Debian/Ubuntu
sudo dnf install libimobiledevice android-tools # Fedora
idevicepair pair
```

**Windows**
1. Download Windows builds of `idevice_id.exe`, `ideviceinfo.exe`, `idevicecrashreport.exe`, and `idevicediagnostics.exe` (e.g. from the [libimobiledevice-win32](https://github.com/libimobiledevice-win32/) project) and place them in `tools/`.
2. Download `platform-tools` for `adb.exe` and place it (with its DLLs) in `tools/`.
3. Install **iTunes** or the **Apple Devices** app from the Microsoft Store — this installs the *Apple Mobile Device USB Driver*, which is required for any USB communication with an iPhone/iPad even when using the bundled CLI tools.
4. If `idevice_id.exe` isn't bundled, PanicLab falls back to enumerating Apple devices via Windows WMI/PnP (`Get-PnpDevice`) and the iTunes pairing registry — this works for basic discovery, but you'll still need `idevicecrashreport.exe` bundled (or on `PATH`) to actually pull panic logs.

> No `pyimobiledevice` Python package is required on any platform — all Apple device interaction goes through the CLI tools above.

## Running PanicLab

**Standalone `.exe`:** just double-click `PanicLab.exe`, or pass a file path as an argument to open it immediately:

```powershell
PanicLab.exe path\to\panic-full-iPhone.ips
```

**From source:**

```bash
python main.py
```

Optionally pass a file path as the first argument to open it immediately:

```bash
python main.py path/to/panic-full-iPhone.ips
```

## Usage

### Apple Analysis

1. Go to the **🍎 Apple** page.
2. Either:
   - **Drag and drop** a `.ips`, `.panic`, or `.txt` panic log onto the drop zone, or
   - Click **📂 Open .ips / .panic** to browse for a file, or
   - Connect a trusted iPhone/iPad over USB, pick it from the device dropdown, and click **⬇ Pull Panic Logs**.
3. PanicLab pulls/parses the log, classifies its source type (`panic-full`, `panic-base`, `analytics`, `sysdiagnose`), and runs it through the Apple hardware-fault detector.
4. Review findings — each shows severity, confidence, the offending log lines (with context), and suggested next steps.
5. Export a Markdown or HTML report from the **Reports** page.

The on-device pull tries multiple strategies in order, so a single phone with no prior crash export still works in most cases:
1. `idevicecrashreport -e <dir>` — full CrashReporter extraction (`.ips` + `panic-full`)
2. `idevicecrashreport -u <udid>` (base64 capture) — `panic-base` blob
3. `idevicediagnostics diagnostics All` — analytics/sysdiagnose bundle

### Android Analysis

1. Go to the **🤖 Android** page.
2. Drag and drop a `kernel.log`, tombstone, `last_kmsg`, or a full `bugreport.zip`, or pull live crash logs from a connected ADB device (tombstone → pstore/ramoops → live `logcat -b kernel -b system -b crash` dump, in that priority order).
3. Review categorized findings (UFS/eMMC, RAM, PMIC, Thermal, CPU/GPU, Modem, Kernel, Watchdog) with severity and confidence.

> App-level crashes (Java/Kotlin exceptions, ANRs) are intentionally **not** analyzed here — this page is scoped to kernel/hardware-level faults.

### Battery Health

1. Go to the **🔋 Battery** page.
2. Either point it at a connected device (live `dumpsys battery` / `batterystats` / `batteryproperties` polling) or drop a bugreport ZIP / dumpsys text file.
3. View health %, cycle count, temperature, voltage, and capacity (current vs. design), with manufacturer-specific parsing for Samsung, Xiaomi, OnePlus, and Pixel devices.

### Devices

Shows a live, auto-refreshing list of every Android and Apple device PanicLab can currently see, with platform, model, and OS version where available.

## Supported Log Formats

| Format | Platform | Extension(s) |
|---|---|---|
| panic-full | Apple | `.panic`, `.txt` |
| panic-base (base64/binary) | Apple | `.txt` |
| Analytics / IPS | Apple | `.ips` |
| sysdiagnose bundle | Apple | `.tar.gz`, `.zip` |
| Tombstone | Android | `.txt`, inside `bugreport.zip` |
| Dumpstate / bugreport | Android | `.zip`, `.txt` |
| ramoops / pstore | Android | `.txt`, `.log` |
| last_kmsg | Android | `.txt`, `.log` |

Dropped `.zip`/`.txt`/`.log`/`.gz` files are automatically routed between the Android and Battery pages by sniffing their contents for crash-related vs. battery-related keywords.

## What Gets Detected

**Apple hardware categories:** NAND/Storage · Battery/Power · Face ID (Secure Enclave) · Display (backlight/TCON/panel) · Charging (PMIC/USB-C) · Audio (codec/speaker amp) · Baseband (cellular modem) · Kernel · Unknown

**Android hardware categories:** UFS/eMMC · RAM · PMIC · Thermal · CPU/GPU · Modem · Kernel · Watchdog · Unknown

Every finding includes:
- `category` — the hardware subsystem implicated
- `title` — short human-readable description
- `severity` — `critical` | `high` | `medium` | `low`
- `confidence` — 0–100 score
- `evidence` — raw log snippets with surrounding context
- `suggestions` — actionable repair/triage steps
- `source_type` — which log format the finding came from
- `line_refs` — originating line numbers for jump-to-evidence

## Configuration

PanicLab stores config and logs in OS-standard locations (via `platformdirs`):

| OS | Config | Logs |
|---|---|---|
| Windows | `%LOCALAPPDATA%\PanicLab\config.json` | `%LOCALAPPDATA%\PanicLab\Logs\paniclab.log` |
| macOS | `~/Library/Application Support/PanicLab/config.json` | `~/Library/Logs/PanicLab/paniclab.log` |
| Linux | `~/.config/PanicLab/config.json` | `~/.local/state/PanicLab/log/paniclab.log` |

Settings available from the **⚙️ Settings** page (persisted automatically on close):

- **Appearance** — theme (`dark` / `light` / `system`)
- **Analysis** — minimum confidence threshold (0–100, default 40), context lines around evidence (0–50, default 5)
- **Reports** — default export format, default output directory
- **Battery** — enable/disable battery analysis, module availability status

## Project Structure

```
PanicLab/
├── main.py                    # App entry point, main window, navigation, config, theming
├── device_manager.py          # Cross-platform device discovery (ADB + libimobiledevice/WMI) and live pulling
├── apple_analyzer.py          # Apple panic log parser & hardware-fault detection engine
├── apple_analysis_page.py     # Apple Analysis page UI (drop zone, device picker, findings view)
├── apple_panic_pull.py        # Multi-strategy iPhone/iPad panic log puller (panic-full/base/analytics/sysdiagnose)
├── android_analyzer.py        # Android kernel crash parser & hardware-fault detection engine
├── android_analysis_page.py   # Android Analysis page UI
├── battery_health_page.py     # Android battery health page UI (live ADB + manufacturer-aware log parsing)
└── tools/                     # (you create this) bundled adb / libimobiledevice binaries
```

Each `*_page.py` module is a self-contained, optional "drop-in" — if it's missing, `main.py` falls back to a disabled stub page rather than failing to start, so you can run PanicLab with a partial checkout while a module is being developed.

## Logging & Troubleshooting

- Logs are written to the OS log directory listed above (`paniclab.log`, rotated at 5 MB × 3 backups) **and** streamed to stdout when running from a terminal.
- The **Help → About PanicLab** menu shows which optional modules loaded successfully (`DeviceManager`, `Android analyzer`, `Apple analyzer`, `Battery health`) — useful for diagnosing a missing/failed import at a glance.
- If a "Pull Panic Logs" / device-pull action fails:
  - Confirm the device is **unlocked** and you tapped **Trust** on it.
  - Confirm the device has actually panicked at least once since its last restore (no crash, no panic log).
  - Check the tool-status indicator dot next to the Apple device picker (🟢 = `idevicecrashreport` + `idevice_id` found, 🟡 = partial, 🔴 = none found — hover for install instructions).
  - On Windows, make sure iTunes/Apple Devices is installed (USB driver) in addition to the bundled CLI tools.

## Platform Notes

- **No `pyimobiledevice` Python dependency** is needed on any OS — all Apple communication is done by shelling out to the libimobiledevice CLI tools.
- On **Windows**, Apple device discovery additionally falls back to **WMI** (`Win32_PnPEntity`) / PowerShell `Get-PnpDevice` and the iTunes pairing registry key under `HKCU\Software\Apple Computer, Inc.\Mobile Device Support\iPhone OS Devices` when `idevice_id` isn't available — recognizing both legacy 40-hex-character UDIDs and the modern 8+16-hex format used since the iPhone XS (2018+).
- All subprocess calls explicitly decode tool output as **UTF-8** rather than relying on the OS locale's default codepage, so non-ASCII device names and log content are handled consistently across Windows, macOS, and Linux.
- Console-window flashing on Windows is suppressed via `CREATE_NO_WINDOW` for every subprocess call.

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl/Cmd+O` | Open Log File |
| `Ctrl/Cmd+Q` | Quit |
| `1`–`7` | Jump to sidebar page N (Dashboard, Devices, Apple, Android, Battery, Reports, Settings) |

## Contributing

Issues and pull requests are welcome. A few things to keep in mind:

- The codebase targets **Python 3.11+** and uses `from __future__ import annotations` plus PEP 604 unions throughout — keep new code consistent with that style.
- Each platform-specific subprocess path (Windows vs. POSIX) should be exercised or at least reasoned through for both branches — this project has been bitten before by Windows-only `UnicodeDecodeError`s from un-pinned subprocess text encoding, so always pass `encoding="utf-8", errors="replace"` explicitly to `subprocess.run(..., text=True)`.
- New detection patterns for `apple_analyzer.py` / `android_analyzer.py` should include realistic evidence snippets and a justified confidence score.

## License

No license file is currently included in this repository. Add one (e.g. MIT, Apache-2.0) before distributing or accepting external contributions.
