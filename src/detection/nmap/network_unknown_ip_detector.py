import json
from collections import defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


def load_network_whitelist(
    whitelist_file: str,
) -> set[str]:
    with open(
        whitelist_file,
        "r",
        encoding="utf-8",
    ) as file:
        whitelist_data = json.load(file)

    if isinstance(whitelist_data, list):
        return set(whitelist_data)

    if isinstance(whitelist_data, dict):
        return set(
            whitelist_data.get("allowed_ips", [])
        )

    return set()


def _unknown_ip_time_range(
    events: list[NetworkEvent],
) -> tuple[str | None, str | None]:
    """
    Calculate the UTC time range of packets
    involving a specific unknown IP address.

    Preserve nanosecond precision.

    If any contributing packet has an invalid
    timestamp, return unknown time bounds.
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


def detect_unknown_network_ips(
    events: list[NetworkEvent],
    whitelist_file: str,
) -> list[ThreatFinding]:
    """
    Detect IP addresses absent from the whitelist.

    Preserve source packet time ranges for each
    unknown IP address independently.
    """

    whitelist = load_network_whitelist(
        whitelist_file
    )

    events_by_ip = defaultdict(list)

    for event in events:

        # Deduplicate the same IP within one packet
        # while considering both source and destination.
        observed_ips = {
            ip_address
            for ip_address in (
                event.src_ip,
                event.dst_ip,
            )
            if ip_address
        }

        for ip_address in observed_ips:

            if ip_address in whitelist:
                continue

            events_by_ip[ip_address].append(
                event
            )

    findings = []

    for ip_address in sorted(events_by_ip):

        first_seen, last_seen = (
            _unknown_ip_time_range(
                events_by_ip[ip_address]
            )
        )

        finding = ThreatFinding(
            title="Unknown Network IP Detected",
            severity="medium",
            description=(
                f"Network traffic involving unknown IP address "
                f"{ip_address} was detected in packet capture telemetry."
            ),
            source="PCAP Network Detection",
            ip=ip_address,
            recommendation=(
                "Investigate the IP address and verify whether the "
                "network communication is authorized."
            ),
            first_seen=first_seen,
            last_seen=last_seen,
        )

        findings.append(finding)

    return findings