from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


def correlate_threats(
    unknown_events: list[SecurityEvent],
    critical_events: list[SecurityEvent],
) -> list[ThreatFinding]:

    findings = []

    critical_map = {
        event.src_ip: event
        for event in critical_events
    }

    for unknown in unknown_events:

        if unknown.src_ip in critical_map:

            critical = critical_map[unknown.src_ip]

            finding = ThreatFinding(
                title="Unknown host with exposed critical service",
                severity="critical",
                description=(
                    f"Host {unknown.src_ip} exposes "
                    f"critical port {critical.dst_port}."
                ),
                source="Threat Correlation Engine",
                ip=unknown.src_ip,
                hostname=unknown.hostname,
                port=critical.dst_port,
                recommendation=(
                    "Verify asset inventory, restrict access "
                    "and investigate host."
                )
            )

            findings.append(finding)

    return findings