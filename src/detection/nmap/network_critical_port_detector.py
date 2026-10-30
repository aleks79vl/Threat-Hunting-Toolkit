import json
from collections import defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


def load_network_critical_ports(
    critical_ports_file: str,
) -> set[int]:
    with open(
        critical_ports_file,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    raw_ports = []

    if isinstance(data, list):
        raw_ports = data

    elif isinstance(data, dict):
        raw_ports = data.get("critical_ports", [])

    critical_ports = set()

    for item in raw_ports:
        if isinstance(item, dict):
            port = item.get("port")
        else:
            port = item

        try:
            critical_ports.add(int(port))
        except (TypeError, ValueError):
            continue

    return critical_ports


def _safe_int(value) -> int | None:
    try:
        if value == "":
            return None

        return int(value)

    except (TypeError, ValueError):
        return None


def _critical_port_time_range(
    events: list[NetworkEvent],
) -> tuple[str | None, str | None]:
    """
    Calculate the UTC time range of packets
    matching a critical network port.

    Preserve nanosecond precision.

    Return unknown time bounds if any
    contributing packet has an invalid timestamp.
    """

    if not events:
        return None, None

    earliest = None
    latest = None

    for event in events:
        packet_time = normalize_packet_time(
            event.timestamp
        )

        if packet_time is None:
            return None, None

        if (
            earliest is None
            or packet_time[0] < earliest[0]
        ):
            earliest = packet_time

        if (
            latest is None
            or packet_time[0] > latest[0]
        ):
            latest = packet_time

    return earliest[1], latest[1]


def detect_network_critical_ports(
    events: list[NetworkEvent],
    critical_ports_file: str,
) -> list[ThreatFinding]:
    """
    Detect network traffic involving critical ports.

    Preserve source packet time ranges for each
    unique connection and critical port.
    """

    critical_ports = load_network_critical_ports(
        critical_ports_file
    )

    # Group matching packets by the same key
    # used by the original detector.
    events_by_connection = defaultdict(list)

    for event in events:
        src_port = _safe_int(event.src_port)
        dst_port = _safe_int(event.dst_port)

        # Prevent a single packet from being counted
        # twice when both ports match the same key.
        matched_connections = set()

        if src_port in critical_ports:
            matched_connections.add(
                (
                    event.src_ip,
                    event.dst_ip,
                    src_port,
                    event.protocol,
                )
            )

        if dst_port in critical_ports:
            matched_connections.add(
                (
                    event.src_ip,
                    event.dst_ip,
                    dst_port,
                    event.protocol,
                )
            )

        for connection_key in matched_connections:
            events_by_connection[connection_key].append(
                event
            )

    findings = []

    for connection_key in sorted(events_by_connection):
        src_ip, dst_ip, port, protocol = connection_key

        first_seen, last_seen = (
            _critical_port_time_range(
                events_by_connection[connection_key]
            )
        )

        finding = ThreatFinding(
            title="Critical Network Port Detected",
            severity="high",
            description=(
                f"Network traffic involving critical port {port} "
                f"was detected between {src_ip} and {dst_ip} "
                f"using protocol {protocol}."
            ),
            source="PCAP Network Detection",
            ip=dst_ip or src_ip,
            port=port,
            recommendation=(
                "Review whether this critical service exposure or "
                "communication is expected and authorized."
            ),
            first_seen=first_seen,
            last_seen=last_seen,
        )

        findings.append(finding)

    return findings
