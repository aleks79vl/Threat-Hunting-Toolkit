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

            consistent_observation = (
                unknown.observation_scope in ("host", "scan")
                and unknown.observation_start is not None
                and unknown.observation_end is not None
                and unknown.observation_start <= unknown.observation_end
                and unknown.observation_scope == critical.observation_scope
                and unknown.observation_start == critical.observation_start
                and unknown.observation_end == critical.observation_end
            )

            finding = ThreatFinding(
                title="Unknown host with exposed critical service",
                severity="critical",
                description=(
                    f"Host {unknown.src_ip} exposes "
                    f"critical port {critical.dst_port}."
                ),
                observation_start=(
                    unknown.observation_start
                    if consistent_observation else None
                ),
                observation_end=(
                    unknown.observation_end
                    if consistent_observation else None
                ),
                observation_scope=(
                    unknown.observation_scope
                    if consistent_observation else None
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