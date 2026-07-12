# Reporting Architecture

## Overview

Threat Hunting Toolkit generates investigation-ready reports from correlated security findings.

The reporting pipeline transforms normalized events into analyst-friendly reports.

---

## Reporting Pipeline

```text
Raw Logs
    ▼
Parsers
    ▼
Normalized Events
    ▼
Detection Engines
    ▼
Threat Correlation
    ▼
Risk Scoring
    ▼
IOC Intelligence
    ▼
MITRE ATT&CK Mapping
    ▼
Timeline
    ▼
JSON Report
HTML Report
Executive Summary
```

---

## Generated Reports

Current reports:

- JSON Report
- HTML Report
- Executive Summary
- MITRE Statistics
- IOC Statistics
- Linux Statistics
- Network Statistics
- Timeline

---

## Report Features

Current reporting capabilities include:

- Executive summary
- Severity distribution
- Threat statistics
- Timeline reconstruction
- MITRE ATT&CK statistics
- IOC intelligence
- Network statistics
- Linux statistics
- Risk scoring
- Analyst recommendations

---

## Future Improvements

Planned reporting enhancements:

- PDF export
- CSV export
- Dashboard mode
- Interactive HTML reports
- Threat graphs
- Executive dashboards