# Threat-Hunting-Toolkit

A modular Python-based Threat Hunting platform designed to collect, normalize, correlate and analyze security events from multiple data sources.

The project demonstrates how a Security Analyst can transform raw security logs into actionable threat intelligence without relying on a full-scale SIEM platform.

---

# Project Goals

Modern security investigations rarely rely on a single log source.

Real-world incidents require analysts to correlate information from:

- Network scanners
- Firewall logs
- Windows Security Events
- Linux authentication logs
- Web server logs
- Endpoint telemetry

This project demonstrates how those independent data sources can be normalized, correlated and converted into investigation reports.

---

# Key Features

✅ Modular architecture

✅ Security event normalization

✅ Threat correlation engine

✅ Risk scoring engine

✅ JSON reporting

✅ HTML reporting

✅ Executive Summary generation

✅ Test-driven development

✅ Extensible parser architecture

---

# Current Architecture

```
                  Raw Security Data
                         │
      ┌──────────────────┼──────────────────┐
      │                  │                  │
   Nmap XML        Firewall Logs     Windows Events
      │                  │                  │
      └──────────────────┼──────────────────┘
                         │
                    Log Parsers
                         │
                  SecurityEvent Model
                         │
                  Detection Engines
                         │
             ┌───────────┴───────────┐
             │                       │
      Unknown Host          Critical Service
             │                       │
             └───────────┬───────────┘
                         │
                 Threat Correlation
                         │
                    ThreatFinding
                         │
                    Risk Scoring
                         │
                  ThreatReport Model
                         │
          ┌──────────────┼──────────────┐
          │              │              │
      JSON Report   HTML Report   Executive Summary
```

---

# Current Detection Pipeline

```
Nmap XML

↓

Parser

↓

SecurityEvent

↓

Unknown Host Detection

↓

Critical Port Detection

↓

Threat Correlation

↓

Risk Scoring

↓

Threat Report

↓

JSON / HTML Report

↓

Executive Summary
```

---

# Current Detection Capabilities

✔ Parse Nmap XML scans

✔ Detect unknown assets

✔ Detect exposed critical services

✔ Correlate multiple findings

✔ Assign risk score

✔ Generate structured findings

✔ Produce JSON reports

✔ Generate HTML reports

✔ Generate Executive Summary

---

# Current Project Structure

```
Threat-Hunting-Toolkit/

├── config/
│   ├── whitelist.json
│   └── risk_scores.json
│
├── data/
│   └── raw/
│
├── reports/
│
├── docs/
│   └── examples/
│
├── src/
│   ├── correlation/
│   ├── detection/
│   ├── models/
│   ├── parsers/
│   ├── reporting/
│   ├── utils/
│   └── main.py
│
├── tests/
│
├── README.md
├── CHANGELOG.md
└── requirements.txt
```

---

# Current Statistics

| Component | Status |
|-----------|--------|
| Python Modules | 12 |
| Detection Engines | 2 |
| Reporting Engines | 3 |
| Threat Models | 3 |
| Supported Log Sources | 1 |
| Unit Tests | **35** |
| Test Status | ✅ 100% Passing |

---

# Example Threat Scenario

Current demo simulates the following investigation:

```
Unknown Host
      │
      ▼
Critical Port (3389)
      │
      ▼
Threat Correlation
      │
      ▼
Critical Finding
      │
      ▼
Risk Score
      │
      ▼
Threat Report
```

Generated finding:

```
Host:
192.168.1.77

Hostname:
unknown-host

Severity:
Critical

Risk Score:
100

Exposed Service:
RDP (3389)

Recommendation:
Verify asset inventory, restrict remote access and investigate the host immediately.
```

---

# Running the Project

Clone repository

```bash
git clone https://github.com/<your_username>/Threat-Hunting-Toolkit.git
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run

```bash
python3 -m src.main
```

Expected output

```
Threat Hunting Report generated successfully.

Output:
reports/threat_report.json

Critical findings:
1
```

---

# Testing

Run all tests

```bash
pytest
```

Current status

```
35 tests passed

100% Passing
```

---

# Engineering Principles

This project follows several engineering principles:

- Modular architecture
- Test-driven development
- Separation of responsibilities
- Extensible parser design
- Independent detection engines
- Reusable reporting components
- Easy integration of new log sources

---

# Development Roadmap

## Completed

- Project architecture
- SecurityEvent model
- ThreatFinding model
- ThreatReport model
- Nmap XML parser
- Unknown Host Detection
- Critical Port Detection
- Threat Correlation Engine
- Risk Scoring Engine
- JSON Report Generator
- HTML Report Generator
- Executive Summary
- Complete reporting pipeline

---

## In Progress

- Firewall parser
- Threat timeline
- Detection improvements

---

## Planned

- Windows Security Event parser
- Sysmon parser
- Linux auth.log parser
- Apache parser
- Nginx parser
- Wireshark PCAP parser
- DHCP parser
- ARP correlation
- IDS / IPS integration
- MITRE ATT&CK mapping
- IOC database
- Threat Intelligence feeds

---

# Release History

## v0.1

Initial architecture

## v0.2

Detection Engine

## v0.3

Reporting Engine

- JSON Reports
- HTML Reports
- Executive Summary
- Risk Scoring

---

# Long-Term Vision

The goal of this project is to evolve from a standalone threat hunting toolkit into a lightweight investigation platform capable of correlating security events across Windows, Linux, Network and Cloud environments.

Future versions will support multiple log sources, advanced threat correlation, MITRE ATT&CK mapping and analyst-friendly investigation reports.

---

# Author

Alex Volov

Cybersecurity Portfolio Project

Python • Threat Hunting • Detection Engineering • Security Automation
