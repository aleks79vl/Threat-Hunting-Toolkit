# Changelog

All notable changes to this project will be documented in this file.

The format follows the principles of semantic versioning.

---

# [v0.3.0] - 2026-06-26

## Overview

This release introduces the first fully functional Threat Hunting pipeline capable of parsing network scan results, detecting suspicious assets, correlating findings and generating investigation reports.

---

## Added

### Core

- Threat Timeline Engine
- Timeline integration into ThreatReport
- Improved ThreatReport data model

### Reporting

- Timeline support in JSON Report
- Timeline support in HTML Report
- Executive Summary improvements
- HTML Report improvements
- Enhanced report generation pipeline

### Documentation

- Complete README redesign
- Updated project architecture
- Updated detection pipeline
- Updated project roadmap
- Updated project statistics
- Improved project presentation

### Testing

- Added Timeline Engine tests
- Added HTML Timeline tests
- Increased automated test coverage
- Total Unit Tests: 39
- 100% Passing

---

## Improved

- Threat investigation workflow
- Report generation pipeline
- Timeline visualization
- Code organization
- Project documentation
- HTML report layout
- Risk reporting

---

## Technical Highlights

Current capabilities include:

- Parse Nmap XML scans
- Normalize security events
- Detect unknown hosts
- Detect exposed critical services
- Correlate multiple findings
- Calculate configurable risk scores
- Generate investigation timelines
- Produce JSON reports
- Produce HTML reports
- Generate executive summaries

---

## Statistics

| Metric | Value |
|--------|------:|
| Detection Engines | 2 |
| Correlation Engines | 1 |
| Report Generators | 4 |
| Timeline Engine | 1 |
| Supported Log Sources | 1 |
| Unit Tests | 39 |
| Test Status | 100% Passing |

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