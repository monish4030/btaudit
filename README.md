# 🔵 BTAudit — Bluetooth Security Auditing Tool

**Made by Monish Paramasivam**

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-green.svg)](https://kali.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/monishparamasivam/btaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/monishparamasivam/btaudit/actions)

> ⚠️ **For authorized environments only.** Scanning devices you don't own or lack written permission to test may be illegal (CFAA, Computer Misuse Act, GDPR). See [docs/LEGAL.md](docs/LEGAL.md).

---

## What it does

BTAudit passively discovers nearby **Bluetooth Classic** and **BLE** devices and tells you:

- Device name, MAC address, RSSI, manufacturer, protocol
- Advertised services and GATT profiles
- Manufacturer-specific data decoded by company ID
- Security misconfigurations (discoverability, SPP, OBEX, PAN/NAP, BLE privacy, medical devices…)
- A **0–100 risk score** per device based on NIST SP 800-121
- Reports in **JSON, CSV, and HTML**

It **never** connects, pairs, injects packets, or exploits anything.

---

## ⚡ Kali Linux — 60-Second Setup

```bash
# 1. Clone
git clone https://github.com/monish4030/btaudit.git
cd btaudit

# 2. Install (requires root for Bluetooth hardware access)
chmod +x install.sh
sudo ./install.sh

# 3. Scan!
sudo btaudit scan --duration 15
```

That's it. Reports are saved to `./reports/`.

---

## Alternative: Run Without Installing

If you just want to try it immediately without `sudo ./install.sh`:

```bash
git clone https://github.com/monishparamasivam/btaudit.git
cd btaudit

# Install Python deps only
pip3 install -r requirements.txt --break-system-packages

# Run directly
sudo python3 run.py scan --duration 15
sudo python3 run.py dashboard
```

---

## Usage

### Scan

```bash
# Basic 15-second passive scan (interactive consent prompt)
sudo btaudit scan --duration 15

# BLE only, 30 seconds, HTML report
sudo btaudit scan --no-classic --duration 30 --format html

# Fully non-interactive (for scripts)
sudo BTAUDIT_AUTHORIZED=1 \
     BTAUDIT_AUTHORIZED_BY="Your Name" \
     BTAUDIT_ENVIRONMENT="Lab Network" \
     btaudit scan --non-interactive --duration 20

# JSON output to pipe into jq
sudo BTAUDIT_AUTHORIZED=1 btaudit scan --non-interactive --json-output \
  | jq '.devices[] | {name, address, risk_score, highest_risk}'
```

### Web Dashboard (real-time)

```bash
sudo btaudit dashboard --port 8080
# Open http://127.0.0.1:8080 in your browser
```

### All commands

```
btaudit scan           Discover and audit nearby devices
btaudit dashboard      Real-time web dashboard
btaudit consent-log    Show authorization audit log
btaudit report FILE    Re-generate reports from existing JSON
btaudit --help         Full help
btaudit --version      Version info
```

---

## Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --duration` | `15` | Scan time in seconds |
| `--ble / --no-ble` | on | Scan BLE devices |
| `--classic / --no-classic` | on | Scan Bluetooth Classic |
| `--active-scan` | off | Active BLE scan (sends scan-request packets) |
| `-o, --output` | `./reports` | Where to save reports |
| `-f, --format` | `all` | `json` / `csv` / `html` / `all` |
| `--non-interactive` | off | Skip prompt (needs `BTAUDIT_AUTHORIZED=1`) |
| `--json-output` | off | Print JSON to stdout |
| `-v, --verbose` | off | Debug logging |

---

## Example Terminal Output

```
  ██████╗ ████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ...
  Bluetooth Security Auditing Tool  v1.0.0  |  Made by Monish Paramasivam

  ✓ Authorization recorded. Hash: a3f7c2b1e9d4f821…

  Scanning for 15s [BLE] [Classic] [Passive]

  ● MacBook Pro [28:CF:E9:11:22:33]
    Protocol: Bluetooth Classic  Manufacturer: Apple  RSSI: -72 dBm (Fair)
    Risk: HIGH  Score: 37/100  Findings: 2
    [BT-001] Device Permanently Discoverable
    [BT-004] Serial Port Profile (SPP) Detected

  ● iPhone 14 Pro [F4:F1:5A:AB:CD:EF]
    Protocol: Bluetooth Low Energy  Manufacturer: Apple  RSSI: -58 dBm (Good)
    Risk: MEDIUM  Score: 15/100  Findings: 1
    [BT-007] BLE Device Using Static Public MAC Address

  ──────────────────────────────────────────────────────
  Scan Complete

  Devices found : 3       Critical : 0
  BLE           : 2       High     : 1
  Classic       : 1       Avg Score: 19/100

  Reports:
  → reports/btaudit_report_20250115_093247.json
  → reports/btaudit_report_20250115_093247.csv
  → reports/btaudit_report_20250115_093247.html
```

---

## Security Findings

| ID | Finding | Severity |
|----|---------|----------|
| BT-001 | Device Permanently Discoverable | MEDIUM |
| BT-002 | Security-Sensitive Service Advertised | HIGH |
| BT-003 | OBEX Object Push (Unauthenticated) | HIGH |
| BT-004 | Serial Port Profile (SPP) | HIGH |
| BT-005 | PAN/NAP Network Bridging | **CRITICAL** |
| BT-006 | Legacy Headset/DUN Profile | MEDIUM |
| BT-007 | BLE Static Public MAC Address | MEDIUM |
| BT-008 | Connectable BLE — No Service Metadata | LOW |
| BT-009 | Elevated TX Power | LOW |
| BT-010 | High-Risk Service Near Device | LOW |
| BT-011 | Medical Device Profile Detected | HIGH |
| BT-012 | No SDP Records Found | INFO |

---

## Docker

```bash
# Build
docker build -t btaudit -f docker/Dockerfile .

# Scan
docker run --rm --net=host --privileged \
  -v $(pwd)/reports:/app/reports \
  -e BTAUDIT_AUTHORIZED=1 \
  -e BTAUDIT_AUTHORIZED_BY="Your Name" \
  -e BTAUDIT_ENVIRONMENT="Test Lab" \
  btaudit scan --non-interactive -o /app/reports

# Dashboard
docker run --rm --net=host --privileged -p 8080:8080 btaudit dashboard
```

---

## Uninstall

```bash
sudo ./uninstall.sh
```

---

## Project Structure

```
btaudit/
├── run.py                      ← Run without installing
├── install.sh                  ← One-command Kali installer
├── uninstall.sh
├── requirements.txt
├── pyproject.toml
├── src/btaudit/
│   ├── cli.py                  ← CLI (scan / dashboard / report)
│   ├── models.py               ← Data models
│   ├── consent.py              ← Authorization gate + packet block
│   ├── oui_db.py               ← 100+ OUI entries, GATT service names
│   ├── scanners/
│   │   ├── ble_scanner.py      ← Passive BLE (bleak)
│   │   └── classic_scanner.py  ← Classic BT (PyBluez / hcitool)
│   ├── analyzers/
│   │   ├── security_analyzer.py← 12 checks + risk scoring
│   │   └── categorizer.py      ← Device category detection
│   ├── reporters/
│   │   ├── json_reporter.py
│   │   ├── csv_reporter.py
│   │   └── html_reporter.py
│   └── dashboard/app.py        ← FastAPI real-time dashboard
├── tests/unit/                 ← 81 unit tests (all passing)
├── docs/
│   ├── USAGE.md
│   └── LEGAL.md
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── examples/reports/           ← Example JSON / CSV / HTML outputs
```

---

## Troubleshooting (Kali Linux)

**`bluetooth.service` not found / no adapter**
```bash
sudo systemctl start bluetooth
hciconfig            # Check adapters
hciconfig hci0 up   # Bring up adapter
```

**BLE scan needs root**
```bash
sudo btaudit scan   # Always run with sudo on Kali
```

**`bleak` not detecting devices**
```bash
sudo bluetoothctl
> scan on            # Verify your adapter works at OS level
> exit
```

**Classic BT scan not working**
```bash
sudo apt install bluez
sudo hciconfig hci0 piscan   # Enable page + inquiry scan for testing
```

---

## Legal

Use only on environments you own or have explicit written authorization to test.
Read [docs/LEGAL.md](docs/LEGAL.md) before use.

---

*Made by **Monish Paramasivam***
