# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

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

#### Testing
- Increased automated test coverage
- 62 passing unit tests
- 100% passing test suite

### Changed

- Main application now processes:
  - Nmap XML
  - Firewall logs
  - Windows Security Events

- Threat reports now include findings from multiple log sources.

- Updated project documentation (README).

---

## [v2.0.0]

### Added

- Nmap XML parser
- Unknown host detection
- Critical port detection
- Threat correlation engine
- Risk scoring
- JSON report generator
- HTML report generator
- Executive summary
- Threat timeline
- Automated unit tests

---

## [v1.0.0]

### Initial Release

- Project structure
- SecurityEvent model
- ThreatFinding model
- ThreatReport model
- Basic architecture