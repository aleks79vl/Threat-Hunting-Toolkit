# Linux Log Analysis Architecture

## Overview

The Linux Log Analysis Engine extends the Threat Hunting Toolkit with host-based Linux telemetry analysis.

The engine processes Linux authentication and system logs, normalizes raw log records into a unified LinuxEvent model, detects suspicious activity, and converts detections into ThreatFinding objects.

Linux findings are integrated into the existing risk scoring, IOC intelligence, MITRE ATT&CK enrichment, timeline, correlation, and reporting pipeline.

---

## Supported Linux Log Sources

Initial Linux telemetry sources:

- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/secure`
- systemd journal text exports

Primary platform coverage:

- Debian
- Ubuntu
- Red Hat compatible Linux distributions
- systemd-based Linux systems

---

## Processing Pipeline

```text
Linux Logs
    ↓
Linux Log Parsers
    ↓
LinuxEvent
    ↓
Linux Detection Engines
    ↓
Linux Threat Findings
    ↓
Linux / Network Correlation
    ↓
Risk Scoring
    ↓
IOC Intelligence
    ↓
MITRE ATT&CK Enrichment
    ↓
Threat Timeline
    ↓
JSON / HTML Reports
```

---

## LinuxEvent Normalization

Raw Linux log entries are normalized into LinuxEvent objects.

Planned normalized fields:

```text
timestamp
hostname
service
process
pid
message
user
source_ip
port
action
status
raw_log
```

The normalized model allows detection engines to analyze Linux telemetry without depending directly on the original log format.

---

## Authentication Detection

Authentication telemetry is primarily collected from:

```text
/var/log/auth.log
/var/log/secure
```

Planned detections:

- Failed SSH login
- Repeated SSH authentication failures
- SSH brute-force activity
- Successful SSH login
- Successful login after repeated failures
- Invalid user authentication attempts

Example flow:

```text
auth.log
    ↓
LinuxEvent
    ↓
SSH Authentication Detector
    ↓
ThreatFinding
```

---

## Telnet Detection

Telnet activity is treated as insecure remote access telemetry.

Planned detections:

- Telnet service activity
- Telnet connection attempts
- Failed Telnet authentication
- Successful Telnet login
- Repeated Telnet login attempts
- External Telnet connections

Telnet network telemetry may also be correlated with PCAP findings.

Example:

```text
PCAP TCP/23 Detection
        +
Linux Telnet Log Event
        ↓
Linux / Network Correlation
        ↓
Confirmed Telnet Activity Correlated
```

---

## Privilege Detection

Linux privilege-related telemetry includes:

- sudo command execution
- repeated sudo failures
- suspicious sudo activity
- root command execution indicators
- user creation
- privileged group membership changes

Planned detections:

```text
Sudo Abuse Detected
Repeated Sudo Failure Detected
New Linux User Detected
Privileged User Modification Detected
```

---

## Persistence Detection

Linux persistence telemetry includes cron and scheduled task activity.

Planned detections:

- new cron jobs
- suspicious cron commands
- cron execution from temporary directories
- download commands in cron jobs
- shell execution from cron
- suspicious persistence indicators

Examples of suspicious paths:

```text
/tmp
/var/tmp
/dev/shm
```

Examples of suspicious commands:

```text
curl
wget
bash
sh
nc
netcat
python
python3
```

---

## Service Manipulation Detection

System logs may expose service lifecycle activity.

Planned detections:

- service started
- service stopped
- service restarted
- repeated service manipulation
- suspicious service changes

Primary telemetry sources:

```text
syslog
systemd
systemctl
```

---

## Linux / Network Correlation

Linux findings may be correlated with Network Detection Engine findings.

Planned correlation examples:

```text
SSH Brute Force Finding
        +
Repeated TCP/22 Network Activity
        ↓
Correlated SSH Attack Activity
```

```text
Telnet Activity Finding
        +
TCP/23 Network Finding
        ↓
Confirmed Telnet Activity Correlated
```

```text
Suspicious DNS Linux Event
        +
PCAP DNS Detection
        ↓
Correlated DNS Threat Activity
```

The correlation layer increases confidence when host and network telemetry describe the same suspicious activity.

---

## ThreatFinding Integration

Linux detectors generate the existing ThreatFinding model.

Example:

```text
title: SSH Brute Force Detected
severity: high
source: Linux Log Detection
ip: 203.0.113.50
hostname: linux-server
port: 22
recommendation: Block the source IP and investigate SSH authentication activity.
```

Linux findings therefore remain compatible with the existing unified reporting pipeline.

---

## Risk Scoring

Linux findings use the existing Risk Scoring Engine.

Planned title-based risk scores:

```text
Failed SSH Login Detected                    40
SSH Brute Force Detected                     85
Successful Login After Failures Detected     90
Telnet Activity Detected                     50
Insecure Telnet Service Detected             65
Failed Telnet Login Detected                 40
Repeated Telnet Login Attempts Detected      75
External Telnet Connection Detected          85
Sudo Abuse Detected                          80
Repeated Sudo Failure Detected               70
New Linux User Detected                      60
Privileged User Modification Detected        90
Suspicious Cron Activity Detected            85
Linux Service Manipulation Detected           70
```

Risk scores remain configurable through:

```text
config/risk_scores.json
```

---

## Reporting Integration

Linux findings will be included in:

- Executive Summary
- Threat Statistics
- Detected Threats
- Threat Timeline
- MITRE ATT&CK Statistics
- IOC Statistics
- JSON Report
- HTML Report

Planned Linux statistics:

```text
Linux events parsed
Linux findings generated
SSH findings
Telnet findings
Privilege findings
Persistence findings
Service findings
```

---

## Testing Strategy

Each Linux component must include automated tests.

Planned test coverage:

```text
LinuxEvent model
auth.log parser
syslog parser
SSH failed login detection
SSH brute-force detection
successful login after failures detection
Telnet activity detection
sudo abuse detection
user and privilege detection
cron activity detection
service manipulation detection
Linux risk scoring
Linux pipeline integration
JSON reporting integration
HTML reporting integration
```

The complete existing test suite must continue to pass after every Linux development block.

---

## Design Principles

The Linux Log Analysis Engine follows the existing Threat Hunting Toolkit architecture:

- modular parsers
- normalized event models
- independent detection engines
- reusable ThreatFinding objects
- configurable risk scoring
- host and network telemetry correlation
- unified reporting
- automated testing

The Linux telemetry layer extends the toolkit without duplicating the existing network, IOC, MITRE ATT&CK, risk scoring, timeline, or reporting engines.