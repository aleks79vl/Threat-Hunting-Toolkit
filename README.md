# Threat Hunting Toolkit

A modular Python framework for Threat Hunting, Threat Intelligence and Security Event Correlation.

A modular Python-based Threat Hunting framework designed to collect,
normalize, correlate and analyze security events from multiple log
sources.

The project demonstrates how a Security Analyst can reduce manual
investigation effort by transforming raw security events into structured
threat intelligence.

------------------------------------------------------------------------

# Project Vision

Modern security operations generate an overwhelming amount of security
telemetry.

The purpose of this project is **not to replace the analyst**, but to
automate repetitive investigation tasks while reducing the risk of human
error.The framework follows a modular architecture inspired by modern Threat Hunting
and SIEM platforms, allowing new log sources, detection engines and intelligence modules 
to be integrated with minimal changes.

The toolkit is designed to:

-   Normalize security events
-   Detect suspicious activity
-   Correlate related findings
-   Calculate risk scores
-   Build investigation timelines
-   Generate investigation-ready reports
-   Support analyst decision making

------------------------------------------------------------------------

# Features

## Log Parsing

-   Nmap XML
-   Windows Security Events
-   Firewall Logs
-   Apache Access Logs

## Threat Detection

-   Unknown IP Detection
-   Critical Port Detection
-   Windows Security Event Detection
-   Firewall Threat Detection
-   Web Attack Detection

## Threat Intelligence

-   IOC Database
-   IOC Loader
-   IOC Matcher
    -  IP
    -  Domain
    -  URL
    -  Hash
-   IOC Enrichment
-   IOC Statistics
-   IOC Risk Scoring

## Threat Analysis

-   Threat Correlation
-   Risk Scoring
-   MITRE ATT&CK Mapping
-   Timeline Generation

## Reporting

-   JSON Report
-   HTML Report
-   IOC Intelligence
-   MITRE Statistics

## Testing

-   108 Automated Unit Tests
-   Full Test Suite Passing

------------------------------------------------------------------------

# Architecture

Logs
    │
    ▼
Parsers
    │
    ▼
Threat Detection
    │
    ▼
Threat Correlation
    │
    ▼
Risk Scoring
    │
    ▼
MITRE ATT&CK
    │
    ▼
IOC Intelligence
    │
    ▼
Timeline
    │
    ▼
JSON Report
HTML Report

------------------------------------------------------------------------

# Detection Pipeline

``` text
Raw Raw Logs
↓
Parsers
↓
Security Events
↓
Detection Engines
↓
Threat Correlation
↓
Risk Scoring
↓
MITRE Mapping
↓
IOC Matching
↓
IOC Risk Scoring
↓
Timeline
↓
JSON / HTML ReportsLogs


```

------------------------------------------------------------------------

# Current Detection Capabilities

-   Detect unknown assets
-   Detect exposed critical services
-   Detect firewall attacks
-   Detect Windows security events
-   Detect SQL Injection
-   Detect XSS attempts
-   Detect Directory Traversal
-   Detect Admin Panel Enumeration
-   Detect Suspicious User Agents
-   Correlate findings
-   Calculate configurable risk scores
-   Generate executive summaries
-   Build investigation timelines
-   Produce JSON reports
-   Produce HTML reports
-   IOC Matching
-   IOC Enrichment
-   MITRE Mapping
-   Threat Intelligence
-   IOC Risk Scoring

------------------------------------------------------------------------

# Generated Reports

## JSON

    reports/threat_report.json

Contains:

- Summary
- Threat Statistics
- Findings
- Timeline
- Risk Scores
- Recommendations
- MITRE ATT&CK Statistics
- MITRE Technique Mapping
- MITRE Tactic Mapping

## HTML

    reports/threat_report.html

Contains:

- Executive Summary
- Threat Statistics
- MITRE ATT&CK Statistics
- Findings Table
- Threat Timeline
- Risk Scores
- Recommendations
- MITRE Technique Mapping
- IOC Statistics
- IOC Matches
- IOC Confidence
- IOC Intelligence
- MITRE Statistics
------------------------------------------------------------------------

# MITRE ATT&CK Integration

Threat Hunting Toolkit enriches detected threats using the MITRE ATT&CK framework.

Each supported detection may include:

- Technique ID
- Technique Name
- ATT&CK Tactic

Reports automatically include:

- Technique statistics
- Tactic statistics
- MITRE mapping

------------------------------------------------------------------------

# Threat Intelligence

The toolkit includes a built-in IOC Intelligence Engine.

Supported indicators:

- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)

Capabilities:

- IOC matching
- IOC enrichment
- IOC statistics
- IOC risk scoring
- JSON integration
- HTML integration

-------------------------------------------------------------------------

# Threat Timeline

The Timeline Engine reconstructs the order of detected events.

Example:

``` text
18:15:01  Unknown host detected
18:15:02  Critical RDP service detected
18:15:03  Threat correlation completed
18:15:03  Risk score assigned
18:15:04  Report generated
```

------------------------------------------------------------------------

# Risk Scoring

Risk values are configurable in:

    config/risk_scores.json

Current severity levels:

  Severity   Typical Meaning
  ---------- -------------------------
  Critical   Immediate investigation
  High       High priority
  Medium     Requires review
  Low        Informational

------------------------------------------------------------------------

# Project Structure

``` text
Threat-Hunting-Toolkit/
├── config/
├── data/
├── docs/
├── reports/
├── src/
│   ├── correlation/
│   ├── detection/
│   ├── models/
│   ├── parsers/
│   ├── reporting/
│   └── utils/
├── tests/
├── README.md
├── CHANGELOG.md
└── requirements.txt
```

------------------------------------------------------------------------

# Installation

``` bash
git clone https://github.com/<your_username>/Threat-Hunting-Toolkit.git
cd Threat-Hunting-Toolkit
pip install -r requirements.txt
```

------------------------------------------------------------------------

# Usage

Run:

``` bash
python3 -m src.main
```

Example output:

``` text
Threat Hunting Report generated successfully.

JSON output file:
reports/threat_report.json

HTML output file:
reports/threat_report.html

Total findings: 25
Critical findings: 4
```

------------------------------------------------------------------------

# Testing

Run:

``` bash
pytest
```

Current status:

``` text
108 passed
100% Passing
```

------------------------------------------------------------------------

# Technologies

-   Python
-   Pytest
-   XML
-   JSON
-   Dataclasses
-   Git
-   GitHub

------------------------------------------------------------------------

# Current Statistics

|           Metric             |     Value    |
|------------------------------|--------------|
| Detection Engines            |       5      |
| Correlation Engines          |       1      |
| Report Generators            |       4      |
| Timeline Engine              |       1      |
| Supported Log Sources        |       4      |
| Unit Tests                   |      108     | 
| Test Status                  | 100% Passing |

------------------------------------------------------------------------

# Roadmap

## Completed

-   Modular architecture
-   Nmap XML parser
-   Unknown Host Detection
-   Critical Port Detection
-   Threat Correlation
-   Risk Scoring
-   Executive Summary
-   JSON Reporting
-   HTML Reporting
-   Threat Timeline
-   Automated testing
-   Firewall Log Parser
-   Firewall Threat Detection
-   Windows Event Parser
-   Windows Event Detection
-   PowerShell Detection
-   Web Log Parser
-   Web Attack Detection
-   IOC Matching


## Next Milestones

-   Linux
-   PCAP
-   Wireshark
-   Nginx
-   Sysmon
-   Sigma
-   YARA
-   Threat Intelligence Feeds
-   MISP
-   OpenCTI
-   Machine Learning
-   Zero-Day Detection
-   MITM Detection
-   Active Directory

------------------------------------------------------------------------

# Long-Term Vision

The long-term objective is to evolve this toolkit into a practical
multi-source Threat Hunting platform capable of correlating security
events across Windows, Linux, Network and Web environments while
generating analyst-friendly investigation reports.

------------------------------------------------------------------------

# Author

Alex Volov

Cybersecurity Portfolio Project

Python • Threat Hunting • Detection Engineering • Security Automation

