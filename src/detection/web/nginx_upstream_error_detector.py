from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


TIMEOUT_MARKERS = (
    "upstream timed out",
    "timed out while",
)

CONNECTION_FAILURE_MARKERS = (
    "connection refused",
    "connect() failed",
    "no live upstreams",
    "prematurely closed connection",
)


def detect_nginx_upstream_errors(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "nginx_error" or not event.upstream:
            continue

        message = event.metadata.get("message", "").lower()

        if any(marker in message for marker in TIMEOUT_MARKERS):
            findings.append(
                ThreatFinding(
                    title="Nginx Upstream Timeout Detected",
                    severity="high",
                    description=(
                        "Nginx timed out while communicating with "
                        f"upstream service {event.upstream}."
                    ),
                    source="Nginx Upstream Error Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review upstream service health, latency and "
                        "reverse-proxy timeout configuration."
                    ),
                )
            )
            continue

        if any(
            marker in message
            for marker in CONNECTION_FAILURE_MARKERS
        ):
            findings.append(
                ThreatFinding(
                    title="Nginx Upstream Connection Failure Detected",
                    severity="high",
                    description=(
                        "Nginx could not establish or maintain a "
                        f"connection to upstream service {event.upstream}."
                    ),
                    source="Nginx Upstream Error Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Verify backend availability, network routing "
                        "and upstream configuration."
                    ),
                )
            )

    return findings