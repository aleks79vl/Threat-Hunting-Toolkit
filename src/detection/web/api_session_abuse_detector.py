from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_api_session_abuse(
    events: list[WebInfrastructureEvent],
    *,
    minimum_distinct_ips: int = 2,
) -> list[ThreatFinding]:
    if minimum_distinct_ips < 2:
        raise ValueError(
            "minimum_distinct_ips must be at least 2"
        )

    session_events = defaultdict(list)

    for event in events:
        if event.source != "api_gateway":
            continue

        session_id_hash = event.metadata.get(
            "session_id_hash",
            "",
        )

        if not session_id_hash:
            continue

        session_events[session_id_hash].append(event)

    findings = []

    for session_id_hash, related_events in session_events.items():
        client_ips = {
            event.client_ip
            for event in related_events
            if event.client_ip
        }

        if len(client_ips) < minimum_distinct_ips:
            continue

        findings.append(
            ThreatFinding(
                title="Potential API Session Abuse",
                severity="medium",
                description=(
                    "The same hashed session identifier was observed "
                    f"from {len(client_ips)} distinct client IP "
                    "addresses."
                ),
                source="API Session Abuse Detector",
                ip=sorted(client_ips)[0],
                hostname=related_events[0].virtual_host,
                port=related_events[0].server_port,
                recommendation=(
                    "Verify whether the session movement is expected; "
                    "consider session binding, token rotation, and "
                    "step-up authentication."
                ),
                ioc_value=session_id_hash,
            )
        )

    return findings