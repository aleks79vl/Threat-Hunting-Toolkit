# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

---

## [v3.1.0] - 2026-07-02

### Added

#### Web Threat Detection

- Apache Access Log parser
- Web Attack Detection engine
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Directory Traversal detection
- Admin Panel Enumeration detection
- Suspicious User-Agent detection

#### Threat Intelligence

- Local IOC Database
- IOC Loader
- IOC Matcher
  - IP matching
  - Domain matching
  - URL matching
  - Hash matching
- IOC Enrichment
- IOC Statistics Engine
- IOC Risk Scoring
- IOC Pipeline Integration

#### Reporting

- IOC information added to JSON reports
- IOC information added to HTML reports
- IOC metadata for every matched finding
- IOC confidence reporting
- IOC source reporting
- IOC description reporting

### Improved

- Threat Hunting pipeline now processes four log sources:
  - Nmap XML
  - Firewall Logs
  - Windows Security Events
  - Apache Access Logs

- Integrated MITRE ATT&CK Mapping with IOC Intelligence.
- IOC matches now automatically enrich Threat Findings.
- IOC confidence now influences Threat Risk Score.
- Enhanced Threat Hunting pipeline with Threat Intelligence layer.
- Improved report generation with IOC Intelligence.
- Improved threat prioritization.
- Increased total detection capabilities.

### Testing

- Added IOC Loader unit tests.
- Added IOC Matcher unit tests.
- Added IOC Enrichment unit tests.
- Added IOC Statistics unit tests.
- Added IOC Risk Scoring unit tests.
- Added IOC HTML reporting tests.
- Added IOC JSON reporting tests.
- Total automated tests increased to **108**.
- Full test suite passing (**108/108**).

### Documentation

- Updated README.
- Updated project architecture.
- Updated detection pipeline.
- Added IOC Intelligence documentation.
- Updated supported capabilities.
- Updated roadmap.
- Updated project statistics.

---

## [v3.0.0] - 2026-06-29

### Added

#### Firewall Support

- Firewall log parser
- Firewall threat detection engine
- Firewall test dataset
- Firewall parser unit tests

#### Windows Support

- Windows Security Event parser
- Windows threat detection engine
- Failed logon detection
- PowerShell activity detection
- User account creation detection
- Audit log cleared detection
- Windows parser unit tests
- Windows detection unit tests

#### Reporting

- Multi-source reporting
- Firewall findings in reports
- Windows findings in reports
- Updated executive summary
- Updated timeline generation

### Testing

- Increased automated test coverage
- 62 passing unit tests
- 100% passing test suite

### Changed

- Main application now processes:
  - Nmap XML
  - Firewall Logs
  - Windows Security Events

- Threat reports now include findings from multiple log sources.
- Updated project documentation (README).

---

## [v2.0.0]

### Added

- Nmap XML parser
- Unknown Host Detection
- Critical Port Detection
- Threat Correlation Engine
- Risk Scoring
- JSON Report Generator
- HTML Report Generator
- Executive Summary
- Threat Timeline
- Automated Unit Tests

---

## [v1.0.0]

### Initial Release

- Project structure
- SecurityEvent model
- ThreatFinding model
- ThreatReport model
- Basic architecture