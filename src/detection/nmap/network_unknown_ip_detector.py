import json

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def load_network_whitelist(whitelist_file: str) -> set[str]:
    with open(whitelist_file, "r", encoding="utf-8") as file:
        whitelist_data = json.load(file)

    if isinstance(whitelist_data, list):
        return set(whitelist_data)

    if isinstance(whitelist_data, dict):
        return set(whitelist_data.get("allowed_ips", []))

    return set()


def detect_unknown_network_ips(
    events: list[NetworkEvent],
    whitelist_file: str,
) -> list[ThreatFinding]:
    whitelist = load_network_whitelist(whitelist_file)

    observed_ips: set[str] = set()

    for event in events:
        if event.src_ip:
            observed_ips.add(event.src_ip)

        if event.dst_ip:
            observed_ips.add(event.dst_ip)

    unknown_ips = observed_ips - whitelist

    findings = []

    for ip_address in sorted(unknown_ips):
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
        )

        findings.append(finding)

    return findings