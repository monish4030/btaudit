# BTAudit Usage Guide

> Made by **Monish Paramasivam**

## Table of Contents

1. [Installation](#installation)
2. [Authorization & Consent](#authorization--consent)
3. [CLI Reference](#cli-reference)
4. [Web Dashboard](#web-dashboard)
5. [Report Formats](#report-formats)
6. [Risk Scoring](#risk-scoring)
7. [Security Findings Reference](#security-findings-reference)
8. [Docker Usage](#docker-usage)
9. [Platform Notes](#platform-notes)
10. [Scripting & Automation](#scripting--automation)

---

## Installation

### Prerequisites

- Python 3.12+
- Bluetooth adapter (hardware)
- Linux: BlueZ (`apt install bluez libbluetooth-dev`)
- macOS: Built-in CoreBluetooth (no extras needed)
- Windows: WinRT Bluetooth API (built-in, Windows 10 1803+)

### Install from source

```bash
git clone https://github.com/monishparamasivam/btaudit
cd btaudit
pip install -e .                    # Core (BLE scanning only)
pip install -e ".[dashboard]"       # + Web dashboard
pip install -e ".[classic]"         # + Bluetooth Classic (Linux/Windows)
pip install -e ".[dev]"             # + Development tools
```

### Verify installation

```bash
btaudit --version
# btaudit, version 1.0.0
```

---

## Authorization & Consent

**BTAudit enforces explicit consent before every scan.** This is non-negotiable.

### Interactive consent (default)

```
btaudit scan
```

You will be shown the legal notice and prompted to:
1. Enter your name or authorization reference number
2. Describe the authorized environment
3. Type `YES I HAVE AUTHORIZATION` to confirm

The consent record is saved to `~/.btaudit/consent_record.json` with a SHA-256 audit hash.

### Non-interactive consent (CI/automation)

```bash
export BTAUDIT_AUTHORIZED=1
export BTAUDIT_AUTHORIZED_BY="Jane Smith – Ref AUTH-2025-042"
export BTAUDIT_ENVIRONMENT="Corporate HQ 3rd Floor"

btaudit scan --non-interactive
```

### View consent audit log

```bash
btaudit consent-log
```

---

## CLI Reference

### `btaudit scan`

```
btaudit scan [OPTIONS]

Options:
  -d, --duration INTEGER     Scan duration in seconds  [default: 15]
  --ble / --no-ble           Scan BLE devices  [default: enabled]
  --classic / --no-classic   Scan Bluetooth Classic devices  [default: enabled]
  --active-scan              Enable BLE active scanning (sends scan-request packets)
  -o, --output PATH          Output directory for reports  [default: ./reports]
  -f, --format [json|csv|html|all]  Report format  [default: all]
  -a, --authorized-by TEXT   Authorization name/reference
  -e, --environment TEXT     Environment description
  --non-interactive          Skip interactive consent prompt
  --json-output              Print JSON to stdout (for scripting)
  -v, --verbose              Enable debug logging
```

**Examples:**

```bash
# Full interactive scan, all formats, 30 seconds
btaudit scan --duration 30

# BLE-only passive scan, JSON output only
btaudit scan --no-classic --format json --duration 20

# Non-interactive scan for CI/scripting
BTAUDIT_AUTHORIZED=1 btaudit scan --non-interactive --json-output | jq '.devices[].name'

# Authorized scan with pre-filled metadata
btaudit scan \
  --authorized-by "Alice – Ticket #SEC-1234" \
  --environment "Server Room B" \
  --duration 60 \
  --output ./audit-reports
```

### `btaudit dashboard`

```
btaudit dashboard [OPTIONS]

Options:
  --host TEXT     Dashboard bind host  [default: 127.0.0.1]
  -p, --port INT  Dashboard port  [default: 8080]
  -v, --verbose   Enable debug logging
```

**Example:**

```bash
btaudit dashboard --port 8080
# Open http://127.0.0.1:8080 in your browser
```

### `btaudit consent-log`

Displays all stored consent records with timestamps and audit hashes.

### `btaudit report`

Re-generate reports from an existing JSON scan file:

```bash
btaudit report ./reports/btaudit_report_20250115_093247.json \
  --format html \
  --output ./new-reports
```

---

## Web Dashboard

The optional web dashboard provides real-time scanning and visualization.

### Starting the dashboard

```bash
# Install dashboard dependencies
pip install btaudit[dashboard]

# Start (local only, recommended)
btaudit dashboard

# Expose on local network (only within authorized LAN)
btaudit dashboard --host 0.0.0.0 --port 8080
```

### Dashboard features

- **Live device discovery** via Server-Sent Events (SSE)
- **Real-time risk scoring** with color-coded badges
- **Filter by risk level** (Critical / High / Medium / Low) or protocol
- **Download reports** in JSON, CSV, or HTML format
- **Activity log** showing discovery events in real time

---

## Report Formats

All reports are written to `./reports/` (configurable with `--output`).

### JSON

Machine-readable, complete data. Suitable for:
- Importing into SIEM/SOAR platforms
- Scripting and automation (`jq`, Python, etc.)
- Feeding into ticketing systems

```bash
# Filter devices with HIGH or CRITICAL risk
cat report.json | jq '.devices[] | select(.highest_risk | IN("HIGH","CRITICAL"))'
```

### CSV

Flat tabular format. One row per device. Suitable for:
- Spreadsheet analysis (Excel, Google Sheets)
- Inventory tracking
- Trend analysis across multiple scans

### HTML

Self-contained, human-readable report with:
- Executive summary statistics
- Per-device cards with risk scores
- Finding details with recommendations
- No external dependencies (works offline)

---

## Risk Scoring

Each device receives a **risk score from 0 to 100** based on its security findings.

| Score Range | Interpretation                     |
|-------------|-------------------------------------|
| 0–9         | No significant concerns             |
| 10–29       | Low risk — informational findings   |
| 30–49       | Medium risk — review recommended    |
| 50–69       | High risk — action required         |
| 70–100      | Critical risk — immediate attention |

### Scoring weights

| Severity | Base Score | Notes                                      |
|----------|------------|--------------------------------------------|
| CRITICAL | 40         | e.g., PAN/NAP network bridging service     |
| HIGH     | 25         | e.g., unauthenticated OBEX, SPP            |
| MEDIUM   | 15         | e.g., permanent discoverability            |
| LOW      | 5          | e.g., static BLE address, high TX power    |
| INFO     | 1          | Informational observation                  |

Multiple findings of the same severity use diminishing returns (each adds 50% of the previous).

---

## Security Findings Reference

| ID     | Title                                     | Severity | Reference                     |
|--------|-------------------------------------------|----------|-------------------------------|
| BT-001 | Device Permanently Discoverable           | MEDIUM   | NIST SP 800-121 §5.1.1        |
| BT-002 | Security-Sensitive Service Advertised     | HIGH     | NIST SP 800-121 §5.3          |
| BT-003 | OBEX Object Push (Unauthenticated)        | HIGH     | CVE-2006-6076                 |
| BT-004 | Serial Port Profile (SPP) Detected        | HIGH     | NIST SP 800-121 §5.3.4        |
| BT-005 | Network Access / PAN Service              | CRITICAL | NIST SP 800-121 §5.3.5        |
| BT-006 | Legacy Headset/DUN Profile                | MEDIUM   | NIST SP 800-121 §4.3          |
| BT-007 | BLE Static Public MAC Address             | MEDIUM   | BT Core Spec 5.4 / GDPR      |
| BT-008 | Connectable BLE — No Advertised Services  | LOW      | BT Core Spec 5.4 §F §3.2     |
| BT-009 | Elevated TX Power                         | LOW      | FCC Part 15 / CE RED          |
| BT-010 | High-Risk Service on Nearby Device        | LOW      | NIST SP 800-121 §3.2          |
| BT-011 | Medical Device Profile Detected           | HIGH     | FDA Cybersecurity 2023        |
| BT-012 | No SDP Service Records Found              | INFO     | NIST SP 800-121 §5.2          |

---

## Docker Usage

### Build and run

```bash
cd docker/
docker build -t btaudit -f Dockerfile ..

# Passive BLE scan (non-interactive)
docker run --rm --net=host --privileged \
  -v $(pwd)/reports:/app/reports \
  -e BTAUDIT_AUTHORIZED=1 \
  -e BTAUDIT_AUTHORIZED_BY="Your Name" \
  -e BTAUDIT_ENVIRONMENT="Test Lab" \
  btaudit scan --non-interactive --duration 20 --output /app/reports

# Web dashboard
docker run --rm --net=host --privileged -p 8080:8080 btaudit dashboard
```

### Docker Compose

```bash
cd docker/
export BTAUDIT_AUTHORIZED=1
export BTAUDIT_AUTHORIZED_BY="Your Name"
export BTAUDIT_ENVIRONMENT="Office Network"

docker compose up scan      # Run one scan
docker compose up dashboard # Start dashboard
```

---

## Platform Notes

### Linux

- Requires BlueZ: `sudo apt install bluez libbluetooth-dev`
- BLE scanning may require `sudo` or CAP_NET_ADMIN capability
- Classic scanning uses `hcitool` as fallback if PyBluez is unavailable

### macOS

- Uses CoreBluetooth via `bleak` — no additional packages needed
- Classic scanning uses `system_profiler SPBluetoothDataType`
- Grant Bluetooth permission when prompted by macOS

### Windows

- Uses WinRT Bluetooth API (Windows 10 1803+) via `bleak`
- Run as Administrator for Classic scanning
- Classic scanning uses PyBluez2 if installed

---

## Scripting & Automation

### JSON pipeline example

```bash
# Scan and extract all HIGH+ risk devices
btaudit scan --non-interactive --json-output 2>/dev/null | \
  jq '[.devices[] | select(.risk_score >= 50)]'

# Count devices by manufacturer
btaudit scan --non-interactive --json-output 2>/dev/null | \
  jq '[.devices[].manufacturer] | group_by(.) | map({(.[0]): length}) | add'
```

### Python integration

```python
import subprocess, json

result = subprocess.run(
    ["btaudit", "scan", "--non-interactive", "--json-output", "--duration", "10"],
    capture_output=True, text=True,
    env={**os.environ, "BTAUDIT_AUTHORIZED": "1", "BTAUDIT_AUTHORIZED_BY": "Script"},
)
session = json.loads(result.stdout)
high_risk = [d for d in session["devices"] if d["risk_score"] >= 50]
print(f"Found {len(high_risk)} high-risk devices")
```
