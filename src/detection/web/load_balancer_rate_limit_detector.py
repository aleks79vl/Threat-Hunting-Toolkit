from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


LOAD_BALANCER_SOURCES = {
    "nginx",
    "haproxy",
    "api_gateway",
}


def _client_identity(event: WebInfrastructureEvent) -> str:
    session_id_hash = event.metadata.get(
        "session_id_hash",
        "",
    )

    if session_id_hash:
        return f"session:{session_id_hash}"

    api_key_id = event.metadata.get("api_key_id", "")

    if api_key_id:
        return f"api_key:{api_key_id}"

    return ""


def detect_rate_limit_bypass(
    events: list[WebInfrastructureEvent],
    *,
    minimum_distinct_ips: int = 3,
) -> list[ThreatFinding]:
    if minimum_distinct_ips < 2:
        raise ValueError(
            "minimum_distinct_ips must be at least 2"
        )

    events_by_identity = defaultdict(list)

    for event in events:
        if event.source not in LOAD_BALANCER_SOURCES:
            continue

        identity = _client_identity(event)

        if not identity or not event.client_ip:
            continue

        events_by_identity[identity].append(event)

    findings = []

    for identity, related_events in events_by_identity.items():
        client_ips = {
            event.client_ip
            for event in related_events
        }

        if len(client_ips) < minimum_distinct_ips:
            continue

        identity_type = identity.split(":", maxsplit=1)[0]

        findings.append(
            ThreatFinding(
                title="Potential Rate Limit Bypass",
                severity="medium",
                description=(
                    f"One {identity_type} identity was observed from "
                    f"{len(client_ips)} distinct client IP addresses."
                ),
                source="Load Balancer Rate Limit Detector",
                ip=sorted(client_ips)[0],
                hostname=related_events[0].virtual_host,
                port=related_events[0].server_port,
                recommendation=(
                    "Apply rate limits to authenticated identities in "
                    "addition to IP addresses, and review whether this "
                    "session or API key is authorized."
                ),
                ioc_value=identity,
            )
        )

    return findings