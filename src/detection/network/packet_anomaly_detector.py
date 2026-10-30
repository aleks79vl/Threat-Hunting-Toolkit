from collections import Counter, defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


REPEATED_CONNECTION_THRESHOLD = 20
ONE_TO_MANY_THRESHOLD = 10

COMMON_PORTS = {
    "53",
    "80",
    "123",
    "443",
}


def _packet_time_range(
    events: list[NetworkEvent],
) -> tuple[str | None, str | None]:
    """
    Calculate the UTC time range of contributing packets.

    Return unknown timestamps if any contributing
    event has an invalid timestamp.
    """

    if not events:
        return None, None

    earliest = None
    latest = None

    for event in events:
        packet_time = normalize_packet_time(event.timestamp)

        if packet_time is None:
            return None, None

        if earliest is None or packet_time[0] < earliest[0]:
            earliest = packet_time

        if latest is None or packet_time[0] > latest[0]:
            latest = packet_time

    return earliest[1], latest[1]


def detect_packet_anomalies(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:

    findings = []

    connection_counter = Counter()
    destinations_by_source = defaultdict(set)
    unusual_ports = set()

    # Preserve contributing packet groups.
    events_by_connection = defaultdict(list)
    events_by_source = defaultdict(list)
    events_by_unusual_port = defaultdict(list)

    for event in events:

        if event.src_ip and event.dst_ip:
            connection_key = (
                event.src_ip,
                event.dst_ip,
                event.dst_port,
                event.protocol,
            )

            connection_counter[connection_key] += 1

            destinations_by_source[event.src_ip].add(
                event.dst_ip
            )

            events_by_connection[connection_key].append(
                event
            )

            events_by_source[event.src_ip].append(
                event
            )

        if (
            event.dst_port
            and event.dst_port not in COMMON_PORTS
        ):
            unusual_key = (
                event.src_ip,
                event.dst_ip,
                event.dst_port,
                event.protocol,
            )

            unusual_ports.add(unusual_key)

            events_by_unusual_port[unusual_key].append(
                event
            )

    # Repeated connections
    for connection, count in connection_counter.items():

        if count >= REPEATED_CONNECTION_THRESHOLD:

            src_ip, dst_ip, dst_port, protocol = connection

            first_seen, last_seen = _packet_time_range(
                events_by_connection[connection]
            )

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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    # One-to-many communication
    for src_ip, destinations in destinations_by_source.items():

        if len(destinations) >= ONE_TO_MANY_THRESHOLD:

            first_seen, last_seen = _packet_time_range(
                events_by_source[src_ip]
            )

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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    # Unusual destination ports
    for src_ip, dst_ip, dst_port, protocol in sorted(
        unusual_ports
    ):

        unusual_key = (
            src_ip,
            dst_ip,
            dst_port,
            protocol,
        )

        first_seen, last_seen = _packet_time_range(
            events_by_unusual_port[unusual_key]
        )

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
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    return findings
