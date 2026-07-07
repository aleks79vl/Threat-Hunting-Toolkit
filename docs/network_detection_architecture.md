# Network Detection Architecture

## Goal

The Network Detection Engine transforms normalized network telemetry into security findings.

PCAP and PCAPNG captures are processed through TShark and converted into NetworkEvent objects.

Network detection modules analyze these events and generate ThreatFinding objects compatible with the existing Threat Hunting pipeline.

## Processing Flow

```text
PCAP / PCAPNG
      ↓
TShark
      ↓
CSV Export
      ↓
Wireshark CSV Parser
      ↓
NetworkEvent[]
      ↓
Network Detection Engines
      ↓
ThreatFinding[]
      ↓
Network Correlation
      ↓
Risk Scoring
      ↓
MITRE ATT&CK Mapping
      ↓
IOC Intelligence
      ↓
Threat Timeline
      ↓
JSON / HTML Reports
```

## Design Principle

Network detection modules must not parse PCAP files directly.

Each detector receives normalized NetworkEvent objects.

This separates packet extraction from threat detection.

```text
Packet Extraction
        ↓
Network Normalization
        ↓
Threat Detection
```

TShark is responsible for packet dissection.

The Threat Hunting Toolkit is responsible for:

- normalization
- detection
- correlation
- risk scoring
- MITRE ATT&CK mapping
- IOC enrichment
- reporting

## Network Detection Engines

The initial Network Detection Engine includes:

### Unknown IP Detection

Detect IP addresses that are not present in the configured whitelist.

Input:

```text
NetworkEvent.src_ip
NetworkEvent.dst_ip
```

Output:

```text
ThreatFinding
```

### Critical Port Detection

Detect communication with configured critical ports.

Input:

```text
NetworkEvent.src_port
NetworkEvent.dst_port
```

Examples:

```text
22
23
445
3389
1433
3306
```

### Network IOC Matching

Extract network indicators and compare them with the IOC Intelligence database.

Supported network indicators:

- IP
- Domain
- URL

Input:

```text
src_ip
dst_ip
dns_query
http_host
http_uri
```

### PCAP Web Attack Detection

Analyze visible HTTP traffic.

Potential detections:

- SQL Injection
- Cross-Site Scripting
- Directory Traversal
- Admin Panel Enumeration

HTTPS encrypted payloads are not inspected unless decrypted traffic is available.

### DNS Suspicious Activity Detection

Analyze DNS query behavior.

Initial detection ideas:

- repeated DNS queries
- unusually long domain names
- high DNS query volume
- suspicious domain patterns

Future extensions:

- DGA detection
- DNS tunneling detection

### Packet Anomaly Detection

Analyze network communication behavior.

Initial anomaly patterns:

- repeated connections
- unusual port usage
- one-to-many communication
- SYN-heavy traffic
- traffic bursts

### MITM / ARP Detection

Analyze ARP and network identity relationships.

Initial detection ideas:

- one IP associated with multiple MAC addresses
- suspicious MAC address changes
- gateway identity conflicts
- ARP spoofing indicators

## Detection Output

Every network detector must return ThreatFinding objects.

Example:

```text
NetworkEvent
      ↓
Critical Port Detector
      ↓
ThreatFinding
```

The network detection layer must not create a separate report format.

All network findings must use the existing reporting pipeline.

## Correlation

Network findings will be correlated before final reporting.

Example:

```text
Unknown IP
    +
Critical Port
    +
IOC Match
    ↓
Correlated Network Threat
```

Another example:

```text
ARP Anomaly
    +
DNS Anomaly
    ↓
Possible MITM Activity
```

## Risk Scoring

Network findings use the existing configurable risk scoring architecture.

Risk values remain stored in:

```text
config/risk_scores.json
```

Detection engines identify suspicious behavior.

Risk scoring assigns investigation priority.

## MITRE ATT&CK

Network findings pass through the existing MITRE ATT&CK mapping layer.

Detection engines must not hard-code ATT&CK logic unless required by the mapping architecture.

## IOC Intelligence

Network findings pass through the existing IOC Intelligence Engine.

Network indicators may include:

- source IP
- destination IP
- DNS domain
- HTTP host
- HTTP URL

IOC matches may increase the final risk score.

## Reporting

Network findings use the existing:

- JSON Report Generator
- HTML Report Generator
- Executive Summary
- Threat Timeline

Network detection is part of the main Threat Hunting pipeline.

## Architecture Boundary

Block 19 is focused on network detection.

The following capabilities are outside the scope of this block:

- full IDS implementation
- deep packet inspection engine
- TLS decryption
- malware binary analysis
- Packer Detection
- YARA scanning
- Sigma rule processing

These capabilities belong to future development blocks.

## Development Order

The Network Detection Engine will be implemented in the following order:

1. Network Detection Architecture
2. PCAP Unknown IP Detector
3. PCAP Critical Port Detector
4. PCAP IOC Matcher
5. PCAP Web Attack Detector
6. DNS Suspicious Activity Detector
7. Packet Anomaly Detector
8. MITM / ARP Detection
9. Network Findings Correlation
10. Network Risk Scoring
11. JSON / HTML Reporting
12. Tests and Full Regression
13. README / CHANGELOG
14. Commit and Push