# Threat Hunting Toolkit Master Roadmap

> Enterprise Threat Hunting Platform Development Plan

---

# Current Status

Current Release

v3.6.0

Detection Architecture Refactoring completed.

Completed

- Block 24: Physical Security Detection Framework
- Physical Security pipeline, correlation and risk scoring
- HTML and JSON Physical Security reporting
- 445 automated tests passed

Current Focus

- Block 25: Web Infrastructure Detection Framework

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

# Block 26

## Threat Intelligence Platform

### IOC

- IOC Database
- Reputation
- IOC Cache
- IOC Scheduler

### Feeds

- MISP
- STIX
- TAXII
- Threat Feeds

### Campaigns

- Threat Actors
- Campaign Detection
- IOC Correlation

---

# Block 27

## Active Directory Detection Framework

### Authentication

- Kerberos
- NTLM
- LDAP
- LDAPS

### AD Attacks

- Golden Ticket
- Silver Ticket
- Kerberoasting
- AS-REP
- Pass-the-Hash
- Pass-the-Ticket

### Domain Controllers

- DCSync
- DCShadow
- SYSVOL
- Replication

### Lateral Movement

- PsExec
- SMB
- WMI
- WinRM
- RDP

### AD Monitoring

- Group Policy
- OU Changes
- Service Accounts
- BloodHound Indicators

---

# Block 28

## AI & Zero-Day Behavioral Detection

### Behavioral Analytics

- User Baselines
- Host Baselines
- Network Baselines
- Process Baselines

### AI

- Unknown Threats
- Zero-Day Indicators
- Risk Prediction
- Behavioral Correlation

---

# Block 29

## Cloud Detection Platform

### Microsoft

- Azure
- Defender XDR
- Microsoft 365
- Entra ID

### Amazon AWS

- CloudTrail
- GuardDuty
- IAM
- Security Hub
- VPC Flow Logs
- CloudWatch

### Google Cloud

- Audit Logs
- SCC
- Google Workspace

---

# Block 30

## Container & Kubernetes Detection Platform

### Docker

- Docker Events
- Container Lifecycle
- Container Escape
- Docker Socket
- Image Integrity

### Kubernetes

- Audit Logs
- kube-apiserver
- kubelet
- etcd
- RBAC
- Pod Security
- Service Accounts
- Secrets
- ConfigMaps
- HostPath
- Network Policies

### Runtime

- containerd
- CRI-O
- runc

### GitOps

- Helm
- ArgoCD
- FluxCD

---

# Block 31

## Real-Time Detection & Response

### Streaming

- Live Detection
- Watch Mode
- Alert Queue

### Notifications

- Email
- Slack
- Microsoft Teams
- Webhooks

### Response

- Automated Response
- Playbooks
- Response Policies

---

# Block 32

## Enterprise Threat Hunting Platform

### Platform

- REST API
- Web Dashboard
- Multi-user
- RBAC
- Scheduled Hunts
- Profiles

### Deployment

- Docker
- Kubernetes
- High Availability

### Plugins

- Detection
- Parser
- Reporting
- Threat Intelligence

---

# Unified Telemetry Layer

Windows

Linux

Active Directory

Firewall

Network

Nmap

Apache

Nginx

Threat Intelligence

USB

Physical Security

Azure

AWS

Google Cloud

Docker

Kubernetes

All telemetry is normalized into a single internal event model before entering the Detection Engine.

---

# Final Goal

Enterprise Threat Hunting Platform

- Multi-source telemetry
- Threat Correlation
- MITRE ATT&CK
- IOC Intelligence
- AI Detection
- Zero-Day Indicators
- Physical Security
- Web Infrastructure
- Active Directory
- Cloud
- Containers
- Real-Time Detection
- Enterprise Dashboard