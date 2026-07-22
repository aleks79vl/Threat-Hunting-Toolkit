from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def is_external_ip(ip: str) -> bool:
    return not (
        ip.startswith("10.")
        or ip.startswith("172.16.")
        or ip.startswith("192.168.")
    )


def detect_firewall_events(
    events: list[SecurityEvent]
) -> list[ThreatFinding]:

    findings = []

    for event in events:
        service = CRITICAL_PORTS.get(event.dst_port)

        if event.event_type == "DENY" and service:
            findings.append(
                ThreatFinding(
                    title="Firewall Blocked Critical Port Access",
                    severity="medium",
                    description=(
                        f"Firewall blocked access from {event.src_ip} "
                        f"to {event.dst_ip}:{event.dst_port} ({service})."
                    ),
                    source="Firewall Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation=(
                        "Review repeated denied attempts and validate firewall rules."
                    )
                )
            )

        elif event.event_type == "ALLOW" and service:
            findings.append(
                ThreatFinding(
                    title="Firewall Allowed Critical Port Access",
                    severity="high",
                    description=(
                        f"Firewall allowed access from {event.src_ip} "
                        f"to {event.dst_ip}:{event.dst_port} ({service})."
                    ),
                    source="Firewall Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation=(
                        "Verify whether access to critical service is authorized."
                    )
                )
            )

        elif is_external_ip(event.src_ip):
            findings.append(
                ThreatFinding(
                    title="External Firewall Connection Attempt",
                    severity="low",
                    description=(
                        f"External IP {event.src_ip} attempted connection "
                        f"to {event.dst_ip}:{event.dst_port}."
                    ),
                    source="Firewall Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation=(
                        "Review external connection attempts for suspicious activity."
                    )
                )
            )

    return findings
