# PCAP Input Architecture

## Goal

The PCAP / Wireshark module will allow Threat Hunting Toolkit to process network traffic captures.

The module will not parse PCAP files directly in Python at the first stage.

Instead, it will use Wireshark / tshark to export selected packet fields into CSV or JSON.

## Processing Flow

PCAP / PCAPNG
    ↓
tshark export
    ↓
CSV / JSON
    ↓
Wireshark Parser
    ↓
NetworkEvent model
    ↓
Detection Engines
    ↓
IOC Intelligence
    ↓
MITRE ATT&CK
    ↓
Risk Scoring
    ↓
Reports

## Supported Input

Initial supported input formats:

- .pcap
- .pcapng
- tshark-exported CSV
- tshark-exported JSON

## Initial Fields

The first parser version should extract:

- timestamp
- source IP
- destination IP
- source MAC
- destination MAC
- protocol
- source port
- destination port
- DNS query
- HTTP host
- HTTP URI

## Future Detection Use Cases

This input layer will support future detection modules:

- suspicious DNS activity
- HTTP IOC matching
- ARP spoofing
- duplicate IP detection
- gateway spoofing
- MITM detection