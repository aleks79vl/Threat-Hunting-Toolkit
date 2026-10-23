# Threat Hunting Toolkit

**A modular Python-based Threat Hunting and Detection Engineering framework for security telemetry analysis, threat detection, and cross-domain correlation.**

Threat Hunting Toolkit processes heterogeneous security telemetry through dedicated detection pipelines for Windows, Linux, network traffic, web infrastructure, firewalls, Nmap, and physical security events.

The framework normalizes events, identifies suspicious activity, correlates findings across security domains, and produces structured JSON and HTML investigation reports.

Network traffic analysis uses TShark to extract structured telemetry from PCAP/PCAPNG captures. The reporting layer includes sensitive-data redaction and HTML escaping mechanisms.

**Latest tagged release:** v3.7.0
**Development status:** Active development
**Automated tests:** 777 passing

---

### Project Vision

Security investigations often require analyzing telemetry from multiple independent systems. Isolated log analysis can miss relationships between suspicious activities occurring across different security domains.

Threat Hunting Toolkit aims to provide a modular, reproducible workflow for security investigations and detection engineering.

The framework enables analysts and developers to:

- Parse and normalize heterogeneous security telemetry.
- Identify suspicious behavior using domain-specific detection modules.
- Analyze network traffic extracted from PCAP/PCAPNG captures using TShark.
- Correlate findings across multiple security domains.
- Enrich findings with Indicators of Compromise (IOCs).
- Associate detections with MITRE ATT&CK techniques.
- Apply configurable risk scoring.
- Generate structured JSON and HTML investigation reports.
- Extend supported telemetry sources and detection capabilities through modular components.

### Project Scope

Threat Hunting Toolkit is an actively developed cybersecurity portfolio and research project focused on threat detection, investigation workflows, and security automation.

It is not presented as a production-ready SIEM, EDR, or commercial SOC platform.

The project prioritizes testable detection logic, modular architecture, transparent reporting, and incremental security improvements.

---

## Project Structure

The project follows a modular architecture with separate components for telemetry parsing, detection, correlation, threat intelligence, security, and reporting.

```text
src/
├── application/
│   ├── traditional_detection_pipeline.py
│   ├── web_infrastructure_application_pipeline.py
│   ├── physical_security_application_pipeline.py
│   ├── cross_domain_analysis_pipeline.py
│   └── threat_report_builder.py
├── config/
├── correlation/
├── detection/
│   ├── common/
│   ├── firewall/
│   ├── linux/
│   ├── network/
│   ├── nmap/
│   ├── physical/
│   ├── web/
│   └── windows/
├── intelligence/
├── mitre/
├── models/
├── parsers/
├── reporting/
├── security/
│   └── redaction.py
├── utils/
└── main.py
```

---

## Release & Development Status

**Latest tagged release:** `v3.7.0` — July 23, 2026
**Current development:** Unreleased
**Automated tests:** 777 passed

Threat Hunting Toolkit is under active development. The current development branch includes improvements introduced after the v3.7.0 release.

### v3.7.0 — Web Infrastructure Detection Framework

This release introduced:

- Normalized Web Infrastructure telemetry.
- Apache access, virtual-host and error log parsers.
- Nginx JSON access and error log parsers.
- API Gateway, HAProxy and WAF/CDN log parsers.
- Detection of suspicious authentication, session and administrative endpoint activity.
- HTTP header manipulation, request smuggling and cache poisoning indicators.
- Backend exposure, SSRF and reverse-proxy-related detections.
- Load-balancer and rate-limit-related detection capabilities.
- Web Infrastructure correlation and reporting.

### Unreleased — Development Improvements

Development since v3.7.0 includes:

**Application Architecture**
- Dedicated application-level orchestration pipelines.
- Cross-domain analysis pipeline.
- Unified ThreatReport builder.
- Standardized pipeline result structures.

**HTTP Header Ingestion — CORE-01**
- Request and response header extraction for Nginx JSON, WAF/CDN and API Gateway telemetry.
- Filtering of malformed HTTP header values.
- Preservation of supported security-relevant headers for detection.
- Positive and negative integration coverage for Header Manipulation, HTTP Request Smuggling, Web Cache Poisoning and Backend Exposure.

**Reporting Security**
- Sensitive-data redaction for supported secrets.
- Removal of `raw_event` fields from exported report structures.
- HTML escaping of dynamic report content.

**Quality Assurance**
- Expanded unit and integration test coverage.
- Full regression suite: **777 tests passing**.

### Development Approach

The project evolves through incremental detection improvements, regression testing, and focused security reviews.

Features under development are tracked separately from released capabilities.

---


## Supported Telemetry Sources

Threat Hunting Toolkit processes security telemetry from multiple domains using dedicated parsers and detection pipelines.

| Domain | Supported Sources | Input Format |
|---|---|---|
| Windows | Windows Security Events | CSV |
| Linux | Authentication Logs, Syslog | Text logs |
| Firewall | Firewall Events | Log files |
| Network Discovery | Nmap Scan Results | XML |
| Network Traffic | Packet Captures | PCAP / PCAPNG |
| Web Infrastructure | Apache Access, Virtual Host and Error Logs | Text logs |
| Web Infrastructure | Nginx Access and Error Logs | JSONL / Text logs |
| Web Infrastructure | API Gateway Events | JSONL |
| Web Infrastructure | HAProxy HTTP Logs | Text logs |
| Web Infrastructure | WAF / CDN Events | JSONL |
| Physical Security | Device and Physical Security Events | JSON |

### Network Traffic Processing

The Network Detection Pipeline uses **TShark** to extract structured packet information from PCAP/PCAPNG files.

Extracted fields include:

- Source and destination IP addresses.
- Source and destination MAC addresses.
- TCP and UDP ports.
- DNS query names.
- HTTP hosts and request URIs.
- ARP protocol and hardware addresses.
- Packet timestamps and protocol information.

TShark exports selected fields to CSV, which is then parsed into normalized network events for detection and correlation.

**Note:** TShark is an external system dependency and must be installed separately. The current network pipeline requires an existing PCAP/PCAPNG file to initiate CSV extraction and analysis.

---


## Detection Capabilities

Threat Hunting Toolkit uses domain-specific detection pipelines to identify suspicious activity in normalized security telemetry.

Detection results depend on the available input data, configured policies, and implemented detection rules.

### Windows Security

- Windows Security Event analysis.
- Rule-based detection of suspicious Windows events.

### Linux Security

- Failed SSH authentication and brute-force indicators.
- Successful authentication following failed login attempts.
- Sudo abuse and privilege-related activity.
- Suspicious cron and service activity.
- Telnet and advanced Telnet activity indicators.
- Suspicious process execution and reverse-shell indicators.
- SSH, systemd, and cron persistence indicators.
- Audit tampering and log-clearing indicators.
- Suspicious file-permission activity.
- Advanced Linux risk scoring and MITRE ATT&CK mapping.

### Network Security

- Unknown IP address detection.
- Critical port exposure detection.
- Network IOC matching.
- Suspicious web traffic indicators.
- DNS activity anomalies.
- Packet anomalies.
- ARP spoofing indicators.
- Network finding correlation.

Network analysis uses structured packet telemetry extracted from PCAP/PCAPNG files through TShark.

### Web Infrastructure Security

**Apache**
- Web shell indicators.
- Legacy web attack detection through the Traditional Detection Pipeline.

**Nginx**
- Reverse-proxy abuse and proxy-chain anomalies.
- Upstream errors and unusual HTTP methods.
- Directory traversal, suspicious uploads, and PHP attack indicators.
- Load-balancer anomalies.

**API Gateway**
- Authentication attack indicators.
- Session abuse and suspicious administrative endpoint access.
- Resource-consumption anomalies.
- Bot and scraping activity indicators.

**HAProxy and WAF/CDN**
- Load-balancer anomalies.
- WAF security event analysis.
- TLS and HTTP protocol metadata anomalies.
- WebSocket upgrade anomalies.
- Configurable web security baseline deviations.

**Cross-Source HTTP Detection**
- Backend exposure indicators.
- HTTP header manipulation.
- HTTP request smuggling indicators.
- Web cache poisoning indicators.
- SSRF indicators.
- Load-balancer session abuse and rate-limit bypass indicators.

HTTP header-based detection depends on the telemetry available from each source. Request and response header ingestion has been verified for Nginx JSON, WAF/CDN, and API Gateway.

### Firewall and Network Discovery

- Firewall event detection.
- Nmap-based unknown IP and critical port detection.
- Correlation of related network discovery findings.

### Physical Security

- USB device activity analysis.
- HID attack indicators.
- External storage activity.
- Bluetooth activity.
- Workstation security events.
- Device policy violations.
- Physical security event correlation.
- Physical risk scoring.

Physical Security detections operate on supplied event telemetry; they do not imply direct real-time monitoring of hardware devices.

### Detection Outputs

Domain pipelines produce structured findings that can be used for cross-domain analysis, risk scoring, threat intelligence enrichment, and investigation reporting.

---


## Threat Intelligence & Cross-Domain Correlation

Threat Hunting Toolkit combines IOC matching, configurable risk scoring, and cross-domain correlation to enrich security findings and support investigations.

### IOC Intelligence

The toolkit uses a local JSON-based IOC database located at `data/ioc_database.json`.

Supported IOC types include:

- IP addresses
- Domains
- URLs
- File hashes

When a matching IOC is found, the corresponding security finding is enriched with IOC type, value, confidence, source, and description.

IOC matching currently uses exact IP comparison and case-insensitive text matching for domains, URLs, and hashes.

### Cross-Domain Correlation

The Cross-Domain Analysis Pipeline supports:

- Apache and Nginx finding correlation.
- Firewall and Web finding correlation.
- IOC and Web finding correlation.
- Consolidation of findings across detection domains.

### Risk Scoring

- Configurable risk scoring using `config/risk_scores.json`.
- IOC-aware risk score adjustments.
- Additional correlation findings generated from supported relationships.

### Current Limitations

- IOC intelligence is loaded from a local database.
- Automatic external Threat Intelligence Feed synchronization is not currently implemented.
- IOC matching returns the first matching indicator.
- Substring-based IOC matching may produce false positives.
- Detection and correlation results depend on available telemetry and implemented rules.

The framework is designed to support further development of threat intelligence and correlation capabilities.

---

## Reporting & Investigation Outputs

Threat Hunting Toolkit consolidates findings from multiple detection pipelines into a unified `ThreatReport` and generates structured investigation outputs.

The reporting layer supports JSON, HTML, and console summaries.

### JSON Reports

The JSON report provides structured security investigation data, including:

- Executive and threat summary information.
- Detection findings and severity levels.
- Risk scores and recommendations.
- MITRE ATT&CK technique and tactic information.
- IOC matching and enrichment metadata.
- Network traffic statistics.
- Linux security and process execution statistics.
- Physical Security statistics and risk scores.
- Web Infrastructure telemetry statistics.

Default output:

`reports/threat_report.json`

JSON reports are suitable for further analysis, automation, and integration with external tools.

### HTML Reports

The HTML report presents investigation findings in a human-readable format.

Available sections include:

- Executive Summary.
- MITRE ATT&CK Statistics.
- Network Traffic Summary.
- Linux Security Statistics.
- Linux Execution Statistics.
- Physical Security Summary.
- Web Infrastructure Telemetry.
- Threat Statistics.
- Detected Threats.
- Threat Timeline.

Default output:

`reports/threat_report.html`

### Console Summary

After processing the configured telemetry sources, the toolkit displays a summary containing:

- Generated report locations.
- Total and critical findings.
- Network events and findings.
- Linux events and findings.
- Physical Security events and findings.
- Physical policy and correlation findings.
- Physical risk score.

### Security & Data Handling

The reporting layer includes mechanisms designed to reduce exposure of sensitive information.

**Sensitive Data Redaction**

- Masks supported sensitive fields, including passwords, API keys, access tokens, authorization values, and cookies.
- Applies pattern-based redaction to supported secret representations.
- Removes `raw_event` fields from JSON export structures.
- Applies redaction to supported dynamic HTML report values.

**HTML Output Protection**

- Escapes supported dynamic text values using Python's `html.escape()`.
- Reduces the risk of HTML injection and cross-site scripting in generated reports.

**Security Limitations**

Redaction is based on defined field names and patterns. It is not a guarantee that every possible credential, token, or sensitive value will be detected.

Reports should be reviewed before being shared externally, particularly when generated from sensitive or production security telemetry.

### Report Generation

Reports are generated by the main application pipeline:

```bash
python3 -m src.main
```

Output paths can be configured through `AppConfig` in `src/config/app_config.py`.


---



## System Architecture

Threat Hunting Toolkit follows a modular, pipeline-based architecture.

Each security domain has dedicated parsing and detection components. Findings from these pipelines are consolidated, correlated, scored, and enriched before the final investigation reports are generated.

### Processing Architecture

```text
                 SECURITY TELEMETRY
                         |
        +----------------+----------------+
        |                |                |
   Windows/Linux     Network/PCAP     Web/Firewall/
      Events          Nmap Scans      Physical Events
        |                |                |
        +----------------+----------------+
                         |
                         v
                 TELEMETRY PARSERS
                         |
                         v
                  DOMAIN PIPELINES
                         |
       +-----------------+-----------------+
       |                 |                 |
   Traditional        Network            Linux
   Detection          Detection          Detection
       |                 |                 |
       +-----------------+-----------------+
                         |
       +-----------------+-----------------+
       |                                   |
 Web Infrastructure                Physical Security
     Detection                         Detection
       |                                   |
       +-----------------+-----------------+
                         |
                         v
                 DOMAIN FINDINGS
                         |
                         v
               CROSS-DOMAIN ANALYSIS
                 - Correlation
                 - Risk Scoring
                 - IOC Enrichment
                 - IOC Risk Scoring
                         |
                         v
                 THREAT REPORT BUILDER
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
         JSON Report  HTML Report  Console Summary
```

### Application Orchestration

The main entry point, `src/main.py`, coordinates the application workflow using `AppConfig`.

Its responsibilities include:

1. Loading configured telemetry sources.
2. Executing domain-specific detection pipelines.
3. Collecting normalized events and security findings.
4. Running cross-domain correlation and enrichment.
5. Building the unified `ThreatReport`.
6. Generating JSON and HTML reports.
7. Printing the investigation summary.

### Domain Pipelines

|      Pipeline         |                        Responsibility                                  |
|-----------------------|------------------------------------------------------------------------|
| Traditional Detection | Windows, Firewall, Nmap, and legacy Web analysis                       |
| Network Detection     | TShark-based PCAP processing and network threat detection              |
| Linux Detection       | Authentication, system activity, execution, and persistence indicators |
| Web Infrastructure    | Apache, Nginx, API Gateway, HAProxy, and WAF/CDN analysis              |
| Physical Security     | Device activity, policy violations, correlation, and risk scoring      |
| Cross-Domain Analysis | Correlation, configurable risk scoring, and IOC enrichment             |

### Design Principles

- **Modularity:** Detection capabilities are organized by security domain.
- **Separation of Concerns:** Parsing, detection, correlation, intelligence, and reporting use dedicated components.
- **Normalized Data:** Domain pipelines operate on structured event models.
- **Extensibility:** New parsers and detectors can be integrated into existing pipelines.
- **Testability:** Unit and integration tests validate detection behavior and processing workflows.
- **Report Security:** Supported sensitive values are redacted during report generation.

### Current Execution Model

The toolkit currently operates as a Python application that processes configured telemetry files and generates investigation reports.

Continuous event collection, real-time streaming, and autonomous response are not part of the current main execution workflow.

---


## Installation

Threat Hunting Toolkit is a Python-based application that processes security telemetry and generates investigation reports.

### Prerequisites

- Python 3.12 (current development and testing environment).
- Git.
- TShark for PCAP/PCAPNG network traffic processing.
- pip for installing Python dependencies.

Python dependencies are listed in `requirements.txt`:

- pytest
- lxml
- pandas
- jinja2

### 1. Clone the Repository

```bash
git clone https://github.com/aleks79vl/Threat-Hunting-Toolkit.git
cd Threat-Hunting-Toolkit
```

### 2. Create a Virtual Environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Python Dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Install TShark

TShark is an external packet-analysis utility distributed with Wireshark. It is not installed through `requirements.txt`.

Install Wireshark/TShark using the appropriate installation method for your operating system.

The toolkit searches for TShark in:

1. The system `PATH`.
2. `/Applications/Wireshark.app/Contents/MacOS/tshark` on macOS.

On Windows and Linux, make sure the `tshark` executable is available in the system `PATH`.

Verify the installation:

```bash
tshark --version
```

On macOS, if TShark is installed inside the Wireshark application but is not in `PATH`, the toolkit can also use its standard application path.

### 5. Verify the Environment

Run the automated test suite:

```bash
python -m pytest -q
```

The latest verified development baseline passed 777 automated tests.

### Installation Notes

- TShark is required when processing an existing PCAP/PCAPNG file through the Network Detection Pipeline.
- The default configuration references sample telemetry and configuration files using relative paths.
- Run the application from the repository root.
- The project is developed and tested with Python 3.12. Compatibility with other Python versions has not yet been systematically verified.
- Python package versions are not currently pinned in `requirements.txt`.
- A passing test suite does not guarantee compatibility with every operating system or dependency version.

---

## Quick Start

Threat Hunting Toolkit can be executed using the default application configuration and the included sample telemetry.

### Run the Toolkit

From the repository root, with the Python virtual environment activated:

```bash
python -m src.main
```

The application executes the configured detection pipelines, performs cross-domain analysis, and generates investigation reports.

### Example Console Output

The following output was verified using the default fixture dataset:

```text
Threat Hunting Report generated successfully.
JSON output file: reports/threat_report.json
HTML output file: reports/threat_report.html
Total findings: 244
Critical findings: 17
Network events parsed: 773
Network findings: 175
Linux events parsed: 13
Linux findings: 14
Physical events parsed: 5
Physical findings: 23
Physical policy findings: 4
Physical correlation findings: 6
Physical risk score: 100
```

### Generated Reports

After execution, the toolkit generates:

- **JSON Report:** `reports/threat_report.json`
- **HTML Report:** `reports/threat_report.html`

The HTML report can be opened in a web browser for investigation and review.

### Using Custom Telemetry

Input files and output paths are configured through `AppConfig` in:

`src/config/app_config.py`

To analyze different datasets, configure the corresponding input file paths before running the application.

### Important Notes

- The example results are based on the default fixture dataset, not live production telemetry.
- Detection counts and risk scores depend on the supplied data.
- TShark must be available when processing PCAP/PCAPNG captures.
- Running the application may overwrite previously generated reports at the configured output paths.


---


## Testing

Threat Hunting Toolkit includes automated unit and integration tests covering telemetry parsing, detection logic, correlation, reporting, and security-related functionality.

### Run the Full Test Suite

From the repository root:

```bash
python -m pytest -q
```

For more detailed test output:

```bash
python -m pytest -v --tb=short
```

### Verified Test Baseline

**Current development baseline: 777 tests passed.**

The full regression suite was successfully executed on Python 3.12 after merging the CORE-01 API Gateway HTTP header improvements into `main`.

### Test Coverage Areas

Automated tests cover:

- Security telemetry parsers.
- Windows, Linux, Network, Web Infrastructure, and Physical Security detection.
- Detection pipelines and cross-domain correlation.
- IOC enrichment and risk scoring.
- JSON and HTML report generation.
- Sensitive-data redaction and HTML escaping.
- Positive and negative security detection scenarios.
- End-to-end Web Infrastructure event processing.

### Testing Limitations

- Test results represent the verified development environment and included test cases.
- Passing tests do not guarantee detection of every attack variant.
- Compatibility across all operating systems and Python versions has not been fully validated.
- Automated test counts may change as the project evolves.

For additional testing information, see `docs/testing.md`.

---


## Project Statistics

The following statistics reflect the verified development environment and the default sample telemetry dataset.

### Development & Testing

|           Metric           |    Value   |
|----------------------------|------------|
| Latest Tagged Release      |   v3.7.0   |
| Development Python Version |    3.12    |
| Automated Tests            |     777    |
| Test Status                | 777 Passed |
| Report Formats             | JSON, HTML |

### Default Dataset — Analysis Results

|            Metric             |  Value  |
|-------------------------------|---------|
| Total Findings                |   244   |
| Critical Findings             |    17   |
| Network Events Parsed         |   773   |
| Network Findings              |   175   |
| Linux Events Parsed           |    13   |
| Linux Findings                |    14   |
| Physical Events Parsed        |     5   |
| Physical Findings             |    23   |
| Physical Policy Findings      |     4   |
| Physical Correlation Findings |     6   |
| Physical Risk Score           | 100/100 |

### Statistics Notes

- These results were verified using `python3 -m src.main` with the default application configuration.
- Finding counts and risk scores depend on the supplied telemetry.
- The reported Physical Risk Score reflects the sample dataset, not an assessment of an actual organization's security posture.
- Automated test results reflect the verified development environment.
- Detection module counts are not included because a consistent definition and verified count have not yet been established.
- These statistics should not be interpreted as production detection performance metrics.

---

## Documentation

Technical documentation covering the architecture, detection pipelines, reporting, and testing of Threat Hunting Toolkit.

### Architecture & Detection

- [Linux Log Detection Architecture](docs/linux_log_architecture.md)
- [Windows Detection Architecture](docs/windows_detection_architecture.md)
- [Network Detection Architecture](docs/network_detection_architecture.md)
- [PCAP Input Architecture](docs/examples/pcap_input_architecture.md)

### Reporting & Testing

- [Reporting Documentation](docs/reporting.md)
- [Testing Documentation](docs/testing.md)

### Project Development

- [Development Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)

Additional historical architecture and refactoring records are available in the `docs/` directory.

---

## Roadmap

Threat Hunting Toolkit is approaching the completion of its planned standalone development scope.

### Completed Milestones

- **Block 24 — Physical Security Detection Framework**
  - Device activity detection, policy evaluation, correlation, and risk scoring.
  - Integration with JSON and HTML reporting.

- **Block 25 — Web Infrastructure Detection Framework**
  - Apache, Nginx, API Gateway, HAProxy, and WAF/CDN telemetry analysis.
  - Web threat detection, correlation, and reporting.

### Current Development Priorities

- Complete the remaining approved CORE-01 improvements.
- Maintain backward compatibility across existing detection pipelines.
- Validate detection, correlation, and reporting workflows.
- Complete regression testing and documentation review.
- Prepare a stable final Toolkit release.

### Additional Planned Work

**Block 26 — Threat Intelligence Enrichment**

Potential improvements to IOC normalization, matching, enrichment, and reporting within the existing Toolkit architecture.

The scope and implementation of this block remain subject to development review.

### Project Completion

The Toolkit completion criteria are defined in [ROADMAP.md](ROADMAP.md).

The project prioritizes validated detection functionality, reliable reporting, reproducible testing, and documented limitations.

---

## Author

**Alex Volov**

Cybersecurity Portfolio Project

Detection Engineering • Threat Hunting • Security Automation • Python