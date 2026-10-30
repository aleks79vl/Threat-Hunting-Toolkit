from collections import defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


def _arp_time_range(
    events: list[NetworkEvent],
) -> tuple[str | None, str | None]:
    """
    Calculate the UTC time range of contributing ARP events.

    Preserve source timestamp precision.
    Return unknown time bounds if any contributing
    event contains an invalid timestamp.
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


def detect_arp_spoofing(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    """
    Detect possible ARP spoofing based on IP-to-MAC conflicts.

    Preserve source packet time ranges for each
    conflicting IP address independently.
    """

    ip_to_macs = defaultdict(set)
    events_by_ip = defaultdict(list)

    for event in events:
        observed_ips = set()

        if event.arp_src_ip and event.arp_src_mac:
            ip_to_macs[event.arp_src_ip].add(
                event.arp_src_mac
            )
            observed_ips.add(event.arp_src_ip)

        if event.arp_dst_ip and event.arp_dst_mac:
            ip_to_macs[event.arp_dst_ip].add(
                event.arp_dst_mac
            )
            observed_ips.add(event.arp_dst_ip)

        # A packet may contain the same IP in both
        # ARP source and destination fields.
        # Include that packet only once per IP.
        for ip_address in observed_ips:
            events_by_ip[ip_address].append(event)

    findings = []

    for ip_address, mac_addresses in sorted(
        ip_to_macs.items()
    ):
        if len(mac_addresses) > 1:

            first_seen, last_seen = _arp_time_range(
                events_by_ip[ip_address]
            )

            findings.append(
                ThreatFinding(
                    title="Possible ARP Spoofing Detected",
                    severity="high",
                    description=(
                        f"IP address {ip_address} was observed with "
                        f"multiple MAC addresses: "
                        f"{', '.join(sorted(mac_addresses))}."
                    ),
                    source="PCAP Network Detection",
                    ip=ip_address,
                    recommendation=(
                        "Investigate possible ARP spoofing or "
                        "Man-in-the-Middle activity."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    return findings
