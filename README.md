# MemoryLens

**MemoryLens** is a local-first memory forensics triage and visualization tool built on **Volatility 3**.  
It runs fully on your own machine (no cloud) and provides a clean UI for exploring memory artifacts, suspicious behaviors, and correlated findings.

MemoryLens is designed for **DFIR, incident response, malware analysis, and defensive security investigations**.

---

## What MemoryLens Does

Given a Windows memory image (`.mem`, `.raw`, `.img`, `.dmp`), MemoryLens:

- Orchestrates **Volatility 3** plugin execution
- Normalizes and correlates artifacts (processes, injections, network, modules, etc.)
- Produces structured case output for reporting and validation
- Presents results through a desktop app (Windows) or web UI (Windows/Linux host)

Memory images and results stay local.

---

## Key Features

- Local-first analysis (no uploads to external services)
- Supports multi‑GB memory images (chunked upload + local import)
- Automated artifact extraction and normalization
- Explainable suspicious process scoring
- Process + network relationship graph (Cytoscape)
- Registry-based persistence enumeration when supported by the image
- Optional deep extraction:
  - memory map dumping for suspicious PIDs
  - strings extraction from dumped regions

---

## Supported Artifacts (Windows)

MemoryLens runs the Windows Volatility 3 plugin set (availability depends on the image, symbols, and acquisition type). Common artifacts include:

### System
- Kernel/OS details (`windows.info`)
- Environment artifacts (`windows.envars`) used to enrich OS context when needed

### Processes & Execution
- Process list (`windows.pslist`)
- Process tree (`windows.pstree`)
- Command line (`windows.cmdline`)
- DLL/module listings (`windows.dlllist`, `windows.ldrmodules`, `windows.modules`, `windows.modscan`)
- Handles (`windows.handles`)
- Tokens/SIDs (`windows.getsids`, `windows.getservicesids`)
- Privileges and sessions (`windows.privileges`, `windows.sessions`)
- Deep scans (`windows.psscan`, `windows.joblinks`, `windows.verinfo`)

### Injection & Memory
- Injection indicators (`windows.malfind`)
- VAD/memory map artifacts (`windows.vadinfo`, `windows.vadwalk`, `windows.memmap`, `windows.virtmap`)
- Optional: memmap dumping and strings extraction for malfind-linked PIDs

### Network
- Network connections (`windows.netscan`, `windows.netstat`)

### Drivers / Kernel Signals
- Callbacks, SSDT, driver scans (`windows.callbacks`, `windows.ssdt`, `windows.driverscan`, etc.)

### Registry (Best-effort)
- Hive discovery (`windows.registry.hivelist`, `windows.registry.hivescan`)
- Persistence keys via PrintKey (`windows.registry.printkey`)
- User activity via UserAssist (`windows.registry.userassist`)
- Certificates store (when supported) (`windows.registry.certificates`)

> Note: Some registry-based plugins may fail on certain images/acquisition types; MemoryLens records errors and continues.

---

## Operating Modes

### Windows Host
- **Desktop app** (pywebview wrapper around local backend)
- Local import (fastest; no HTTP upload)

### Linux Host
- **Web UI** (Flask server) in your browser
- Useful for analysts who prefer a Linux workstation but analyze Windows memory images

---

## Requirements

### Host OS
- Windows 10/11 (desktop mode)
- Linux (server mode)

### Software
- Python **3.10** or **3.11** (recommended)
- Internet access for initial symbol downloads (Volatility behavior)

### Dependencies
- Volatility 3 (installed via pip)
- `capstone` (recommended for certain plugins)

---

## Installation

### 1) Clone
```bash
git clone https://github.com/<your-username>/MemoryLens.git
cd MemoryLens
```

### 2) Create and activate a virtual environment

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies

**Core (Windows + Linux)**
```bash
pip install -r requirements.txt
```

**Windows desktop UI**
```powershell
pip install -r requirements-win.txt
```

### 4) Verify Volatility
```bash
python -m volatility3.cli -h
```

---

## Running MemoryLens

### Windows (Desktop)
```powershell
python main_desktop.py
```

### Linux (Web UI)
```bash
python main_server.py
```

Then open:
- `http://127.0.0.1:5111`

---

## Using MemoryLens

### Importing a memory image

MemoryLens supports two ingestion methods:

#### A) Desktop Local Import (Recommended)
- Click **Import local file**
- Select a memory image
- Analysis begins immediately
- No HTTP upload and no browser buffering issues

#### B) Chunked Upload
- Used automatically for large images
- Shows upload progress and avoids timeouts

### Output structure
Each case is stored locally under:

```
data/cases/<case_id>/
├── memory.img
├── case.json         # normalized analysis results used by the UI
├── case_raw.json     # raw plugin outputs + invocations + errors
├── raw/              # per-plugin stdout/stderr outputs
└── dumps/            # optional memmap dumps and extracted strings (when enabled)
```

---

## Memmap Dump + Strings (Malfind-linked)

When enabled, MemoryLens can:
1. Identify suspicious PIDs from `windows.malfind`
2. Run:
   - `windows.memmap --dump --pid <PID>`
3. Extract ASCII and UTF‑16LE strings from dumped regions
4. Expose results in the UI (and in `case_raw.json`)

This is useful for quickly surfacing:
- URLs / C2 indicators
- embedded commands
- PowerShell artifacts
- encoded payload markers
- suspicious PE strings

---

## Troubleshooting

### A plugin fails (rc=1 / rc=2)
- This is common in memory forensics depending on:
  - acquisition method
  - symbol resolution
  - memory image integrity
- MemoryLens records the stderr and continues.

Check:
```
data/cases/<case_id>/raw/*.stderr.txt
```

### Handles plugin complains about capstone
Install capstone:
```bash
pip install capstone
```

### Registry plugins fail (PrintKey/UserAssist/Certificates)
Some images do not support Volatility’s registry layer properly. MemoryLens will log the error and continue with other artifacts. Use alternative indicators (processes, command lines, injection, netscan, dumped-region strings) to proceed.

---

## Packaging a Windows Executable (EXE)

MemoryLens can be packaged into a Windows executable using **PyInstaller**.

### 1) Install build tooling
In your venv:
```powershell
pip install pyinstaller
```

### 2) Build
If you have a spec file:
```powershell
pyinstaller -y build\memorylens.spec
```

If you want a quick one-file build (example):
```powershell
pyinstaller --noconfirm --clean --name MemoryLens --windowed main_desktop.py
```

### 3) Output
Your executable will be under:
- `dist\MemoryLens\MemoryLens.exe` (folder build), or
- `dist\MemoryLens.exe` (one-file build, depending on flags)

> Tip: Ensure your build includes the `frontend/` folder and any required templates/static assets. A spec file is the most reliable way to include these assets.

---

## Security & Legal Notes

- MemoryLens runs locally; no memory images are transmitted externally.
- Symbol downloads occur via Volatility’s normal behavior (e.g., Microsoft symbol servers).
- Use only on memory images you are legally authorized to analyze.

---

## License

Choose a license that matches your intent (MIT is common for security tooling). Add a `LICENSE` file to the repository accordingly.

---

## Author

Ahmad  
Defensive Security / DFIR
