# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

---

# Changelog

---

## Unreleased

### Added

- Physical Security Detection Framework
- USB, HID, storage, Bluetooth and workstation event analysis
- Physical attack-chain correlation and risk scoring
- Physical Security sections in HTML and JSON reports
- Physical Security JSON-report tests

### Verification

- 444 automated tests passed
- HTML and JSON reports generated successfully

## v3.6.0

### Added

- Structured detection package architecture
- Dedicated detection namespaces
- Detection architecture documentation

### Changed

- Detection modules reorganized into technology-specific packages
- Updated imports across the project
- Improved project maintainability
- Improved scalability
- Cleaner repository structure

### Verification

- 360 automated tests passed
- HTML reports verified
- JSON reports verified
- Threat Hunting pipeline verified

### Architecture

Detection modules are now organized as:

- common
- firewall
- linux
- network
- nmap
- web
- windows

---

## v3.5.0 - 2026.07.12


### Added

- Linux Log Detection Engine
- Linux Security Statistics
- Linux Execution Statistics
- Linux HTML Reporting
- Linux JSON Reporting
- Linux Executive Summary
- Linux Integration Tests
- MITRE ATT&CK Summary in Executive Report
- Linux Detection Architecture Documentation

### Improved

- HTML Report Generator
- Executive Summary Generator
- Report Architecture
- Threat Correlation Pipeline
- Detection Statistics
- Report Formatting
- Documentation
- README

### Testing

- 360 automated tests passing
- 100% test success rate

### Current Capabilities

Supported log sources:

- Windows Security Events
- Linux Authentication Logs
- Linux System Logs
- Firewall Logs
- Apache Logs
- PCAP / PCAPNG
- Wireshark CSV
- Nmap XML

Current Detection Modules:

- Windows Detection
- Linux Detection
- Network Detection
- Web Attack Detection
- IOC Detection
- MITRE ATT&CK Mapping
- Threat Correlation
- Threat Timeline
- Risk Scoring

### Statistics

- 214 total findings
- 7 critical findings
- 773 network events analyzed
- 175 network findings
- 13 Linux events parsed
- 14 Linux findings

---

## [3.4.0] - 2026-07-09

### Added

- Linux authentication log parser for `/var/log/auth.log`
- Linux system log parser for `/var/log/syslog`
- Unified Linux event model
- SSH failed login detection
- SSH brute-force detection
- Successful login after repeated failures detection
- Telnet activity detection
- Sudo abuse detection
- Linux user privilege activity detection
- Suspicious cron activity detection
- Linux service manipulation detection
- Linux security statistics generator
- Linux statistics integration into JSON reports
- Linux statistics integration into HTML reports

### Changed

- Extended the unified findings pipeline with Linux threat findings
- Extended console reporting with Linux event and finding counters
- Extended HTML reporting with Linux security statistics
- Extended JSON reporting with Linux security statistics

### Testing

- Added Linux parser tests
- Added Linux event model tests
- Added Linux detection tests
- Added Linux risk score tests
- Added Linux statistics tests
- Full regression suite: 239 tests passed

---

## [v3.3.0] - 2026-07-07

### Added

#### Network Detection Engine

- Network Detection Architecture documentation
- PCAP Unknown IP detector
- PCAP Critical Port detector
- PCAP IOC detector
- PCAP Web Attack detector
- DNS Suspicious Activity detector
- Packet Anomaly detector
- MITM / ARP Spoofing detector
- Network Findings Correlation engine

#### Network Detection Coverage

- Unknown IP detection from PCAP traffic
- Critical port detection from PCAP traffic
- IOC matching against network indicators
- HTTP web attack detection from PCAP traffic
- Suspicious DNS activity detection
- Repeated network connection detection
- One-to-many communication detection
- Unusual destination port detection
- ARP spoofing / MITM indicator detection

#### Risk Scoring

- Added title-based risk scoring rules
- Added network detection risk scoring
- Added MITM and ARP spoofing risk scores
- Added correlated network threat risk scores
- Preserved existing severity-based and bonus-based scoring logic

#### Reporting

- Network findings included in JSON reports
- Network findings included in HTML reports
- Network detections included in unified ThreatReport pipeline
- Network correlation findings included in reports

#### Testing

- Added unit tests for network unknown IP detection
- Added unit tests for network critical port detection
- Added unit tests for network IOC detection
- Added unit tests for network web attack detection
- Added unit tests for DNS suspicious activity detection
- Added unit tests for packet anomaly detection
- Added unit tests for MITM / ARP spoofing detection
- Added unit tests for network findings correlation
- Added unit tests for network risk scoring
- Total automated tests increased to 165
- Full test suite passing (165/165)

### Changed

- Main pipeline now includes Network Detection Engine
- PCAP telemetry now generates ThreatFinding objects
- Network findings are merged into the unified findings pipeline
- Network findings now pass through risk scoring
- Network findings now pass through IOC enrichment
- JSON and HTML reports now include network detections
- Total findings increased from 25 to 200 on the integration dataset
- Critical findings increased from 4 to 6 on the integration dataset

### Validated

- 773 NetworkEvent objects parsed from PCAP integration dataset
- 175 network findings generated
- 200 total findings generated
- 6 critical findings generated
- Full pipeline validated from PCAP to JSON and HTML reports

---

## [v3.2.0] - 2026-07-04

### Added

#### PCAP / Wireshark Support

- PCAP and PCAPNG input architecture
- TShark dependency detection
- macOS Wireshark embedded TShark discovery
- PCAP to CSV export
- PCAP to JSON export
- Wireshark CSV parser
- NetworkEvent normalized network model

#### Network Traffic Analysis

- Network event normalization
- Protocol statistics
- DNS query extraction
- HTTP request statistics
- Network traffic summary generation

#### Reporting

- Network traffic statistics in JSON reports
- Network Traffic Summary in HTML reports
- Protocol statistics reporting
- DNS query statistics reporting
- HTTP request statistics reporting

#### Testing

- Added NetworkEvent unit tests
- Added PCAP exporter unit tests
- Added Wireshark CSV parser unit tests
- Added network statistics unit tests
- Added real PCAP integration test
- Registered pytest integration test marker
- Total automated tests increased to 122
- Full test suite passing (122/122)

### Changed

- Main application pipeline now processes PCAP network captures
- TShark is used as the packet dissection engine
- Network traffic is normalized into NetworkEvent objects
- Main pipeline now reports the number of parsed network events
- JSON and HTML reports now include network traffic statistics

### Validated

- Real PCAP dataset successfully processed
- 773 network events parsed from integration capture
- TCP traffic successfully normalized
- DNS traffic successfully normalized
- Real DNS query data successfully extracted

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