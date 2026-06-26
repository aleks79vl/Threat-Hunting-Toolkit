# Threat-Hunting-Toolkit

Threat-Hunting-Toolkit is a Python-based cybersecurity project designed to collect, normalize, analyze and correlate security events from multiple log sources.

## Features

- Network Log Analysis
- Windows Event Analysis
- Linux Log Analysis
- Web Server Log Analysis
- Threat Detection
- Event Correlation
- MITRE ATT&CK Mapping
- HTML & JSON Reporting

## Supported Log Sources

- Wireshark (PCAP)
- Firewall Logs
- DHCP Logs
- ARP Tables
- Router Logs
- Nmap XML
- Windows Security Events
- PowerShell Logs
- Sysmon
- Linux auth.log
- Syslog
- Apache
- Nginx
---

# Demo

## Run the Project

From the repository root execute:

```bash
python3 -m src.main
```

Expected output:

```text
Threat Hunting Report generated successfully.
Output file: reports/threat_report.json
Total findings: 1
Critical findings: 1
```

---

## Generated Report

The application automatically generates:

```text
reports/threat_report.json
```

The report contains:

- Executive summary
- Threat statistics
- Correlated findings
- Severity distribution
- Recommendations

---

## Current Detection Pipeline

```
Nmap XML
      │
      ▼
Nmap Parser
      │
      ▼
SecurityEvent
      │
      ▼
Unknown IP Detector
      │
      ▼
Critical Port Detector
      │
      ▼
Threat Correlation Engine
      │
      ▼
ThreatFinding
      │
      ▼
ThreatReport
      │
      ▼
JSON Report
```

---

## Current Detection Capabilities

✔ Parse Nmap XML scans

✔ Detect unknown hosts

✔ Detect critical exposed services

✔ Correlate multiple detections

✔ Generate structured threat findings

✔ Produce JSON reports

---

## Current Project Statistics

| Component | Status |
|----------|--------|
| Python Modules | 9 |
| Detection Modules | 2 |
| Correlation Engine | ✓ |
| Reporting Engine | ✓ |
| Supported Log Sources | 1 |
| Unit Tests | 26 |
| Test Status | 100% Passing |

---

## Current Threat Scenario

The demo project currently detects the following scenario:

```
Unknown Host
        +
Critical Port (RDP)
        +
Threat Correlation
        =
Critical Finding
```

Example:

```
IP Address:
192.168.1.77

Critical Service:
RDP (3389)

Severity:
Critical

Recommendation:
Verify asset inventory, restrict remote access and investigate the host.
```

---

## Project Roadmap

### Completed

- Project architecture
- SecurityEvent model
- ThreatFinding model
- ThreatReport model
- Nmap XML parser
- Unknown IP detection
- Critical Port detection
- Threat Correlation Engine
- JSON Report Generator

### In Progress

- Risk Scoring Engine
- HTML Report Generator
- Executive Summary
- Threat Timeline

### Planned

- Firewall Log Parser
- Windows Event Parser
- Sysmon Parser
- Linux Log Parser
- Apache / Nginx Parser
- DHCP & ARP Correlation
- Wireshark PCAP Parser
- IDS / IPS Support
- MITRE ATT&CK Mapping

---

## Development Status

Current Version:

**v0.2**

Current Test Coverage:

**26 Unit Tests — All Passing**
