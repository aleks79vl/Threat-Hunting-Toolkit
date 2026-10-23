# Threat Hunting Toolkit — Development Roadmap

> Roadmap for the standalone Python threat detection and security telemetry analysis toolkit.

---

# Current Status

## Latest Tagged Release

**v3.7.0**

The project continues to evolve beyond the latest tagged release.

## Completed Development Milestones

- **Block 24 — Physical Security Detection Framework**
  - Physical Security event analysis and detection.
  - Device-policy evaluation and attack-chain correlation.
  - Physical risk scoring.
  - JSON and HTML reporting integration.

- **Block 25 — Web Infrastructure Detection Framework**
  - Apache, Nginx, API Gateway, HAProxy, and WAF/CDN telemetry processing.
  - Web Infrastructure detection and correlation.
  - HTTP request and response metadata analysis.
  - JSON and HTML reporting integration.

## Current Development Focus

**CORE-01 — HTTP Header Telemetry Improvements**

- Nginx JSON request/response header support merged.
- WAF/CDN request/response header support merged.
- API Gateway request/response header support merged.
- Remaining CORE-01 work is not yet marked complete.

## Verified Development Baseline

- **Python:** 3.12
- **Automated tests:** 777 passed
- **Execution model:** Local, configuration-driven telemetry analysis
- **Reports:** JSON and HTML

These results describe the verified development baseline, not production performance or compatibility across all environments.

---

# Block 24 — Completed

## Physical Security Detection Framework

### Delivered

- USB, HID, storage, Bluetooth and workstation event detection
- Device-policy enforcement
- Physical attack-chain correlation
- Physical risk scoring
- Physical Security HTML reporting
- Physical Security JSON reporting
- Unit and integration test coverage

---

# Block 25 — Completed

## Web Infrastructure Detection Framework

### Foundation

- Normalized Web Infrastructure Event model
- Request ID and Trace ID support
- Virtual host, upstream and backend fields
- Response time and response size telemetry
- Safe handling and redaction of sensitive headers

### Apache

- Access Logs
- Error Logs
- Virtual Hosts
- Web Shell Detection

### Nginx

- Access Logs
- Error Logs
- Reverse Proxy Abuse
- Upstream Errors
- HTTP Method Abuse
- Directory Traversal
- Upload Abuse
- PHP Attacks

### API and Authentication

- Credential Stuffing and Brute Force
- Session Abuse
- Admin Endpoint Access
- API Gateway Logs
- API Resource Consumption
- Bot and Scraping Detection

### Reverse Proxy

- X-Forwarded-For
- Proxy Chains
- Backend Exposure
- Header Manipulation
- SSRF Indicators
- HTTP Request Smuggling Indicators
- Cache Poisoning Indicators

### Load Balancers

- Nginx Load Balancer
- HAProxy
- Session Abuse
- Rate Limit Bypass

### WAF and Protocol Telemetry

- WAF / CDN Event Normalization
- TLS Metadata
- HTTP/1.1 and HTTP/2 Metadata
- WebSocket Upgrade Events

### Web Correlation
- Apache + Nginx
- Firewall + Web
- IOC + Web
- Threat Intelligence + Web baseline matching
- Deep Threat Intelligence enrichment deferred to Block 26

### Definition of Done

- Parsers, detectors and correlation pipeline integrated into `main.py`
- HTML and JSON reporting integrated
- Unit, integration and backward-compatibility tests added
- Full test suite passes
- README, CHANGELOG and roadmap updated
- Commit and push completed

---

# Block 26 — Planned

## Threat Intelligence Enrichment

**Scope:** Extend the existing IOC analysis capabilities of Threat Hunting Toolkit without introducing a continuously running threat intelligence platform.

### Existing Foundation

- Local IOC database stored in `data/ioc_database.json`.
- IOC loading and matching capabilities.
- IOC-based analysis integrated with detection and correlation workflows.

### Planned Improvements

- Improve IOC normalization and validation.
- Extend IOC matching and enrichment capabilities.
- Improve correlation between IOC matches and security findings.
- Improve threat intelligence context in JSON and HTML reports.
- Add unit and integration tests for new enrichment functionality.
- Document supported IOC formats, matching behavior, and limitations.

### Future Research

The following capabilities may be evaluated separately and are not committed deliverables of Block 26:

- STIX-based IOC import.
- TAXII and MISP interoperability.
- Optional ingestion of external threat intelligence data.
- Threat actor and campaign context based on supported evidence.

### Out of Scope

- Continuously running IOC synchronization services.
- Background feed schedulers.
- Centralized, multi-user threat intelligence management.
- Real-time threat intelligence infrastructure.
- Enterprise Threat Intelligence Platform development.

### Completion Criteria

- New enrichment capabilities integrate with the existing Toolkit execution model.
- Existing IOC matching behavior remains backward compatible.
- Automated tests validate new functionality and regression scenarios.
- Documentation and reporting accurately describe supported capabilities.


---

# Threat Hunting Toolkit — Completion Criteria

## Project Objective

Complete Threat Hunting Toolkit as a standalone, configuration-driven Python tool for security telemetry analysis, threat detection, event correlation, and investigation reporting.

The Toolkit is not intended to become an enterprise monitoring platform.

## Completion Checklist

- [ ] Complete the remaining approved CORE-01 development tasks.
- [ ] Resolve critical defects identified during final regression testing.
- [ ] Verify that existing detection pipelines remain operational.
- [ ] Verify cross-domain correlation and IOC matching functionality.
- [ ] Validate JSON and HTML report generation.
- [ ] Verify sensitive-data redaction in supported reporting workflows.
- [ ] Execute the complete automated regression test suite successfully.
- [ ] Review and update README, ROADMAP, CHANGELOG, and relevant technical documentation.
- [ ] Complete a final review of project architecture, dependencies, and known limitations.
- [ ] Prepare and validate the final Toolkit release.

## Scope Control

Any additional feature must be evaluated against the agreed Toolkit scope before implementation.

Future research directions must not automatically become mandatory Toolkit completion requirements.

## Definition of Complete

Threat Hunting Toolkit may be considered complete when:

1. All agreed mandatory Toolkit functionality is implemented.
2. Critical regression tests pass.
3. Reports and documented execution workflows are validated.
4. Remaining known limitations are documented.
5. The final release is reviewed and approved.
