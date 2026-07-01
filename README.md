# Threat-Hunting-Toolkit

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
error.

The toolkit is designed to:

-   Normalize security events
-   Detect suspicious activity
-   Correlate related findings
-   Calculate risk scores
-   Build investigation timelines
-   Generate investigation-ready reports
-   Support analyst decision making

------------------------------------------------------------------------

# Current Features

## Detection

- Unknown Host Detection
- Critical Port Detection
- Firewall Threat Detection
- Windows Event Detection
- Web Attack Detection
- Threat Correlation Engine
- Risk Scoring Engine

## Reporting

- JSON Report Generator
- HTML Report Generator
- Executive Summary Generator
- Threat Timeline Generator

## Supported Log Sources

- Nmap XML
- Firewall Logs
- Windows Security Events
- Apache Access Logs

## MITRE ATT&CK Integration

- Automatic ATT&CK technique mapping
- ATT&CK tactic mapping
- Threat enrichment with MITRE metadata
- MITRE statistics generation
- MITRE statistics in JSON reports
- MITRE statistics in HTML reports

## Engineering

- Modular architecture
- Configurable detection rules
- Whitelist support
- Unit-tested components

------------------------------------------------------------------------

# Architecture

``` text
                 Raw Security Logs
                        │
     ┌──────────────────┼──────────────────┐
     │                  │                  │
  Nmap XML       Firewall Logs      Windows Events
     │                  │                  │
     └──────────────────┼──────────────────┘
                        │
                   Log Parsers
                        │
                 SecurityEvent Model
                        │
                 Detection Engines
                        │
              Threat Correlation Engine
                        │
                 Risk Scoring Engine
                        │
               Threat Timeline Engine
                        │# Current Features


                  ThreatReport Model
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
      JSON Report   HTML Report   Executive Summary
```

------------------------------------------------------------------------

# Detection Pipeline

``` text
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
Threat Timeline
   ↓
Threat Report
   ↓
JSON / HTML Reports
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
85 passed
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
| Unit Tests                   |      74      | 
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


## Next Milestones

### Linux

-   auth.log
-   syslog
-   sudo logs

### Web

-   Nginx

### Threat Intelligence

-   MITRE ATT&CK Mapping
-   IOC Matching
-   Threat Intelligence feeds
-   Sigma rules

### Active Directory

-   Domain Controller Events
-   Group Policy Events

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

