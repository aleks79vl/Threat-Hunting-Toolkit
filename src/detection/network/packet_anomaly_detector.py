from collections import Counter
from collections import defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


REPEATED_CONNECTION_THRESHOLD = 20
ONE_TO_MANY_THRESHOLD = 10

COMMON_PORTS = {
    "53",
    "80",
    "123",
    "443",
}


def detect_packet_anomalies(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    findings = []

    connection_counter = Counter()
    destinations_by_source = defaultdict(set)
    unusual_ports = set()

    for event in events:
        if event.src_ip and event.dst_ip:
            connection_key = (
                event.src_ip,
                event.dst_ip,
                event.dst_port,
                event.protocol,
            )

            connection_counter[connection_key] += 1
            destinations_by_source[event.src_ip].add(event.dst_ip)

        if event.dst_port and event.dst_port not in COMMON_PORTS:
            unusual_ports.add(
                (
                    event.src_ip,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                )
            )

    for connection, count in connection_counter.items():
        if count >= REPEATED_CONNECTION_THRESHOLD:
            src_ip, dst_ip, dst_port, protocol = connection

            findings.append(
                ThreatFinding(
                    title="Repeated Network Connection Detected",
                    severity="medium",
                    description=(
                        f"Repeated connection pattern detected: "
                        f"{src_ip} -> {dst_ip}:{dst_port} "
                        f"over {protocol}. Observed {count} times."
                    ),
                    source="PCAP Network Detection",
                    ip=dst_ip,
                    port=dst_port,
                    recommendation=(
                        "Review whether repeated communication is expected "
                        "or indicates beaconing/scanning behavior."
                    ),
                )
            )

    for src_ip, destinations in destinations_by_source.items():
        if len(destinations) >= ONE_TO_MANY_THRESHOLD:
            findings.append(
                ThreatFinding(
                    title="One-to-Many Network Communication Detected",
                    severity="high",
                    description=(
                        f"Source IP {src_ip} communicated with "
                        f"{len(destinations)} unique destination IPs."
                    ),
                    source="PCAP Network Detection",
                    ip=src_ip,
                    recommendation=(
                        "Investigate possible scanning, lateral movement, "
                        "or automated network activity."
                    ),
                )
            )

    for src_ip, dst_ip, dst_port, protocol in sorted(unusual_ports):
        findings.append(
            ThreatFinding(
                title="Unusual Destination Port Detected",
                severity="medium",
                description=(
                    f"Network traffic to unusual destination port {dst_port} "
                    f"was observed between {src_ip} and {dst_ip} "
                    f"using protocol {protocol}."
                ),
                source="PCAP Network Detection",
                ip=dst_ip or src_ip,
                port=dst_port,
                recommendation=(
                    "Review whether this port usage is expected for the "
                    "environment."
                ),
            )
        )

    return findings