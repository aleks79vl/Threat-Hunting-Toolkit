from collections import defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def detect_arp_spoofing(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    """
    Detect possible ARP spoofing based on IP-to-MAC conflicts.
    """

    ip_to_macs = defaultdict(set)

    for event in events:
        if event.arp_src_ip and event.arp_src_mac:
            ip_to_macs[event.arp_src_ip].add(event.arp_src_mac)

        if event.arp_dst_ip and event.arp_dst_mac:
            ip_to_macs[event.arp_dst_ip].add(event.arp_dst_mac)

    findings = []

    for ip_address, mac_addresses in sorted(ip_to_macs.items()):
        if len(mac_addresses) > 1:
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
                )
            )

    return findings