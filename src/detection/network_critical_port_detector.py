import json

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def load_network_critical_ports(critical_ports_file: str) -> set[int]:
    with open(critical_ports_file, "r", encoding="utf-8") as file:
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


def detect_network_critical_ports(events: list[NetworkEvent],
    critical_ports_file: str,) -> list[ThreatFinding]:
    critical_ports = load_network_critical_ports(critical_ports_file)

    detected = set()

    for event in events:
        src_port = _safe_int(event.src_port)
        dst_port = _safe_int(event.dst_port)

        if src_port in critical_ports:
            detected.add(
                (
                    event.src_ip,
                    event.dst_ip,
                    src_port,
                    event.protocol,
                )
            )

        if dst_port in critical_ports:
            detected.add(
                (
                    event.src_ip,
                    event.dst_ip,
                    dst_port,
                    event.protocol,
                )
            )

    findings = []

    for src_ip, dst_ip, port, protocol in sorted(detected):
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
        )

        findings.append(finding)

    return findings