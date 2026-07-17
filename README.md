# Threat Hunting Toolkit

A modular Python framework for Threat Hunting, Detection Engineering and Security Event Correlation.

The toolkit transforms raw security telemetry into structured threat intelligence by collecting, normalizing, correlating and analyzing events from multiple security data sources.

---

# Project Vision

Modern infrastructures generate security events from many independent systems.

Threat Hunting Toolkit provides a modular investigation pipeline that enables analysts to:

- Normalize heterogeneous log formats
- Detect suspicious activity
- Correlate security findings
- Enrich events with Threat Intelligence
- Map detections to MITRE ATT&CK
- Calculate configurable risk scores
- Generate analyst-ready reports

The project is designed as a modular framework where new log sources and detection engines can be integrated with minimal architectural changes.

---

# Project Structure

src/

├── correlation/
├── detection/
│   ├── common/
│   ├── firewall/
│   ├── linux/
│   ├── network/
│   ├── nmap/
│   ├── web/
│   └── windows/
│
├── intelligence/
├── mitre/
├── models/
├── parsers/
├── reporting/
└── utils/

---

# Current Release **Version:** **v3.6.0**

### What's New in v3.6.0

- Reorganized all detection modules into dedicated technology packages
- Improved maintainability and scalability
- Updated import architecture across the project
- Added architecture documentation
- Preserved full backward functionality
- 360 automated tests passed successfully

### Highlights

- Detection Architecture Refactoring
- Technology-based Detection Packages
- Linux Detection Engine
- Linux Security Statistics
- Linux Execution Statistics
- Windows Security Event Detection
- Firewall Detection
- Network Detection Engine
- IOC Intelligence
- MITRE ATT&CK Integration
- Threat Correlation
- Threat Timeline
- Executive Summary
- HTML Report Generator
- JSON Report Generator
- Enterprise-grade automated test suite (360 tests)

---

# Supported Platforms

Current supported telemetry sources:

- Windows Security Events
- Linux Authentication Logs
- Linux System Logs
- Firewall Logs
- Apache Access Logs
- PCAP / PCAPNG
- Wireshark CSV
- Nmap XML

---

# Detection Capabilities

Current detection modules include:

### Windows

- Windows Security Event Detection
- PowerShell Detection
- Critical Service Detection

### Linux

- SSH Brute Force Detection
- Failed Authentication Detection
- Successful Login After Failures
- Sudo Abuse Detection
- User Privilege Detection
- Suspicious Cron Activity
- Service Manipulation Detection

### Network

- Unknown IP Detection
- Critical Port Detection
- IOC Detection
- Web Attack Detection
- DNS Suspicious Activity
- Packet Anomaly Detection
- MITM / ARP Spoofing Detection
- Network Threat Correlation

### Physical Security

- USB Device Detection
- HID, BadUSB and Rubber Ducky Detection
- External Storage Monitoring
- Bluetooth Device and File-Transfer Detection
- Workstation Session Monitoring
- Device-Policy Enforcement
- Physical Attack-Chain Correlation
- Physical Risk Scoring

### Web

- SQL Injection Detection
- XSS Detection
- Directory Traversal Detection
- Admin Panel Enumeration
- Suspicious User-Agent Detection

---

# Threat Intelligence

Integrated intelligence capabilities:

- IOC Matching
- IOC Statistics
- IOC Enrichment
- IOC Risk Scoring
- MITRE ATT&CK Mapping
- Threat Correlation
- Threat Timeline Reconstruction

---

# Reporting

Generated outputs:

### JSON Report

Contains:

- Executive Summary
- Findings
- Timeline
- Risk Scores
- IOC Intelligence
- MITRE Statistics
- Linux Statistics
- Network Statistics
- Physical Security Statistics and Risk Score

### HTML Report

Includes:

- Executive Summary
- Interactive Findings
- MITRE Statistics
- IOC Intelligence
- Linux Statistics
- Linux Execution Statistics
- Network Statistics
- Physical Security Summary and Event Statistics
- Threat Timeline

---

# Architecture

```
Raw Logs
      ▼
Parsers
      ▼
Normalized Security Events
      ▼
Detection Engines
      ▼
Threat Correlation
      ▼
Risk Scoring
      ▼
IOC Intelligence
      ▼
MITRE ATT&CK Mapping
      ▼
Timeline Generation
      ▼
JSON / HTML Reports
```

---

# Project Structure

```
Threat-Hunting-Toolkit/

config/
data/
docs/
reports/
src/
tests/

README.md
ROADMAP.md
CHANGELOG.md
requirements.txt
```

---

# Installation

```bash
git clone https://github.com/<username>/Threat-Hunting-Toolkit.git

cd Threat-Hunting-Toolkit

pip install -r requirements.txt
```

---

# Quick Start

```bash
python3 -m src.main
```

Example output:

```text
Threat Hunting Report generated successfully.

JSON output file:
reports/threat_report.json

HTML output file:
reports/threat_report.html

Total findings: 214
Critical findings: 7

Network events parsed: 773
Network findings: 175

Linux events parsed: 13
Linux findings: 14
```

---

# Testing

Run:

```bash
pytest
```

Current status:

```text
360 passed

100% Passing
```

---

# Current Statistics

|         Metric                 |         Value             |
|--------------------------------|--------------------------:|
| Detectops moduls               |            35             |
| Correlation Engines            |             3             |
| Report Generators              |             2             |
| Supported Platform             | Windows / Linux / Network |
| Network Events Parsed          |           773             |
| Network Findings               |           175             |
| Linux Events Parsed            |            13             |
| Linux Findings                 |            14             |
| Physical Events Parsed         |             5             |
| Physical Findings              |            23             |
| Physical Risk Score            |           100             |
| Total Findings                 |           237             |
| Critical Findings              |            16             |
| Automated Tests                |           445             |
| Test Status                    |        100% Passing       |

---

# Documentation

Detailed technical documentation:

- docs/linux_log_architecture.md
- docs/network_detection_architecture.md
- docs/reporting.md
- docs/testing.md
- docs/project_structure.md
- ROADMAP.md
- CHANGELOG.md

---

# Roadmap

The project is actively evolving.

Upcoming development areas include:

- Advanced Windows Detection
- DLL Threat Detection
- Registry Analysis
- Sysmon Integration
- Router Log Analysis
- USB Device Detection
- Nginx Detection
- Sigma Rules
- YARA Integration
- Threat Intelligence Feeds
- Machine Learning
- Zero-Day Detection
- AI-assisted Threat Hunting
- Cloud Detection
- Real-Time Threat Detection
- Autonomous Threat Response

See **ROADMAP.md** for the complete development roadmap.

---

# Author

**Alex Volov**

Cybersecurity Portfolio Project

Detection Engineering • Threat Hunting • Security Automation • Python