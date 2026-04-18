# VolOrch — Volatility Plugin Orchestrator

> Automated memory forensics threat detection through cross-plugin correlation and weighted scoring.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![Volatility3](https://img.shields.io/badge/Volatility-3.x-red?style=flat-square)](https://github.com/volatilityfoundation/volatility3)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square)]()

---

## The Problem

Every memory forensics analyst runs Volatility plugins individually and correlates findings manually.

`malfind` shows you injected memory.  
`netscan` shows you active connections.  
Neither tells you they belong to the **same process**.  
Neither gives you a **threat score**.  
Neither says — *this is your highest priority.*

**VolOrch does.**

---

## What It Does

VolOrch orchestrates multiple Volatility 3 plugins, correlates their outputs by PID, scores each process using a weighted signal rubric, and produces actionable threat reports — all from a single command.

```
memory.dump
     ↓
┌─────────────────────────┐
│   Plugin Runner         │  → pstree, netscan, malfind, cmdline, dlllist
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Extractor             │  → Typed, PID-keyed objects with built-in heuristics
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Correlation Engine    │  → 7 cross-plugin signals, weighted scoring (0-100)
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Report Generator      │  → PDF + JSON + HTML with Chart.js visualizations
└─────────────────────────┘
```

---

## Features

- **Plugin Orchestration** — runs 5 Volatility 3 plugins automatically
- **Cross-Plugin Correlation** — matches findings across plugins by PID
- **Weighted Threat Scoring** — 7 signals, scores 0–100, severity: CRITICAL / HIGH / MEDIUM / LOW
- **Rich Terminal Output** — color-coded threat table + severity distribution chart
- **Three Report Formats** — PDF, JSON, and interactive HTML report
- **Single Command** — full analysis pipeline from one entry point

---

## Threat Signals

| Signal | Weight | Description |
|---|---|---|
| `malfind_executable_memory` | 30 | RWX memory region detected |
| `malfind_and_network_overlap` | 25 | Injected memory + active external connections on same PID |
| `external_network_connection` | 20 | Active outbound connection |
| `suspicious_cmdline` | 20 | Encoded commands, LOLBins, PowerShell abuse |
| `malfind_hit` | 15 | Non-executable suspicious memory region |
| `suspicious_dll_path` | 15 | DLL loaded from Temp / AppData |
| `no_parent_process` | 10 | PPID not found in process list |
| `unusual_process_name` | 10 | Known suspicious process names |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/volorch.git
cd volorch

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- Volatility 3 (`pip install volatility3`)
- See `requirements.txt` for full dependency list

---

## Usage

```bash
# Full analysis — PDF + JSON + HTML reports
python main.py /path/to/memory.dump

# Only show HIGH severity and above
python main.py /path/to/memory.dump --min-score 50

# JSON report only
python main.py /path/to/memory.dump --json-only

# Custom output directory
python main.py /path/to/memory.dump --output-dir /tmp/results

# With additional symbol directory
python main.py /path/to/memory.dump --symbol-dirs /path/to/symbols
```

---

## Sample Output

```
  STEP 1/3 — Running Volatility Plugins
  pstree       ████████  48 rows
  netscan      ████████  118 rows
  malfind      ██        11 rows
  cmdline      ████████  48 rows
  dlllist      ████████  2305 rows

  STEP 2/3 — Extracting & Correlating

  Processes flagged : 22
  CRITICAL           : 2
  MEDIUM             : 6
  LOW                : 14

┌───────┬──────────────────┬───────┬──────────────┐
│  PID  │ Process          │ Score │ Severity     │
├───────┼──────────────────┼───────┼──────────────┤
│  1856 │ wmpnetwk.exe     │  75   │ ● CRITICAL   │
│   472 │ svchost.exe      │  75   │ ● CRITICAL   │
│   604 │ explorer.exe     │  40   │ ● MEDIUM     │
│  2424 │ mspaint.exe      │  40   │ ● MEDIUM     │
└───────┴──────────────────┴───────┴──────────────┘
```

---

## Project Structure

```
volorch/
├── volorch/
│   ├── __init__.py
│   ├── runner.py          # Volatility 3 plugin execution engine
│   ├── extractor.py       # Normalize plugin output → typed objects
│   ├── correlator.py      # Cross-plugin correlation + threat scoring
│   ├── reporter.py        # PDF + JSON report generation
│   ├── html_reporter.py   # HTML report with Chart.js visualizations
│   └── visualizer.py      # Rich terminal output
├── reports/               # Generated reports (gitignored)
├── main.py                # CLI entry point
├── requirements.txt
└── README.md
```

---

## Supported Dump Formats

| Format | Source |
|---|---|
| `.raw` | WinPmem, LiME |
| `.vmem` | VMware / VirtualBox snapshots |
| `.dmp` | Windows crash dumps |
| `.elf` | VirtualBox core dumps |

---

## Tested On

- Windows 7 SP1 x64
- Windows 10 x64
- MemLabs CTF memory images

---

## Roadmap

- [ ] Configurable weights via `config/weights.yaml`
- [ ] MITRE ATT&CK technique mapping per signal
- [ ] Additional plugins: `psxview`, `hollowprocesses`, `svcscan`
- [ ] False positive suppression for known-clean system processes
- [ ] ML-based scoring (Phase 2)

---

## Author

Built by **Adarsh** — Assistant Professor, Digital forensics researcher.

- Instagram / LinkedIn: [@italkforensics](https://www.instagram.com/italkforensics) [Adarsh V P](https://www.linkedin.com/in/adarsh-v-p

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

VolOrch is intended for lawful forensic analysis, academic research, and educational purposes only. Always obtain proper authorization before analyzing any system or memory image.
