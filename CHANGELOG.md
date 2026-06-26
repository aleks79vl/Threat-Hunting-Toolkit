# Changelog

All notable changes to this project will be documented in this file.

The format follows the principles of semantic versioning.

---

# [v0.3.0] - 2026-06-26

## Overview

This release introduces the first fully functional Threat Hunting pipeline capable of parsing network scan results, detecting suspicious assets, correlating findings and generating investigation reports.

---

## Added

### Core Architecture

- SecurityEvent data model
- ThreatFinding data model
- ThreatReport data model
- Modular project architecture

### Parsers

- Nmap XML parser

### Detection Engine

- Unknown Host Detection
- Critical Port Detection

### Correlation

- Threat Correlation Engine

### Risk Analysis

- Risk Scoring Engine

### Reporting

- JSON Report Generator
- HTML Report Generator
- Executive Summary Generator

### Configuration

- Whitelist support
- Risk score configuration

### Documentation

- Complete project README
- Project architecture
- Detection pipeline
- Roadmap
- Development principles

### Testing

- 35 Unit Tests
- 100% Passing

---

## Improved

- Project folder organization
- Reporting workflow
- Detection pipeline
- Configuration management
- Project documentation
- Code readability
- Test coverage

---

## Technical Highlights

Current capabilities:

- Parse Nmap XML scans
- Normalize security events
- Detect unknown hosts
- Detect exposed critical services
- Correlate multiple findings
- Calculate risk score
- Generate investigation reports
- Produce JSON reports
- Produce HTML reports
- Generate executive summaries

---

## Statistics

Current project metrics:

| Metric | Value |
|--------|-------|
| Python Modules | 12 |
| Detection Engines | 2 |
| Report Generators | 3 |
| Threat Models | 3 |
| Supported Log Sources | 1 |
| Unit Tests | 35 |
| Passing Tests | 100% |

---

## Next Release (v0.4)

Planned features:

- Firewall Log Parser
- Windows Security Event Parser
- Linux Authentication Parser
- Sysmon Parser
- Apache Parser
- Nginx Parser
- Wireshark PCAP Parser
- Threat Timeline
- IOC Support
- MITRE ATT&CK Mapping

---

# [v0.2.0]

## Added

- Threat Correlation Engine
- Critical Port Detection
- Unknown Host Detection
- JSON reporting
- Initial reporting pipeline
- Unit tests

---

# [v0.1.0]

## Initial Release

### Added

- Initial repository
- Project architecture
- Python project structure
- Core configuration
- GitHub repository
- Testing framework
- Initial documentation

---