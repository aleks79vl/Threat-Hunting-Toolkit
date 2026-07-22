from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


LOAD_BALANCER_SOURCES = {
    "nginx",
    "haproxy",
}


def detect_load_balancer_session_abuse(
    events: list[WebInfrastructureEvent],
    *,
    minimum_distinct_backends: int = 2,
) -> list[ThreatFinding]:
    if minimum_distinct_backends < 2:
        raise ValueError(
            "minimum_distinct_backends must be at least 2"
        )

    session_events = defaultdict(list)

    for event in events:
        if event.source not in LOAD_BALANCER_SOURCES:
            continue

        session_id_hash = event.metadata.get(
            "session_id_hash",
            "",
        )

        if not session_id_hash or not event.backend:
            continue

        session_events[session_id_hash].append(event)

    findings = []

    for session_id_hash, related_events in session_events.items():
        backends = {
            event.backend
            for event in related_events
        }

        if len(backends) < minimum_distinct_backends:
            continue

        findings.append(
            ThreatFinding(
                title="Load Balancer Session Affinity Anomaly",
                severity="medium",
                description=(
                    "The same hashed session identifier was routed to "
                    f"{len(backends)} distinct backends: "
                    f"{', '.join(sorted(backends))}."
                ),
                source="Load Balancer Session Detector",
                ip=related_events[0].client_ip,
                hostname=related_events[0].virtual_host,
                port=related_events[0].server_port,
                recommendation=(
                    "Verify sticky-session configuration and ensure "
                    "session storage is shared or correctly replicated "
                    "between backend servers."
                ),
                ioc_value=session_id_hash,
            )
        )

    return findings