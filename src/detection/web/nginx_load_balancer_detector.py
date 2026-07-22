from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_nginx_load_balancer_anomalies(
    events: list[WebInfrastructureEvent],
    *,
    minimum_total_requests: int = 20,
    imbalance_threshold: float = 0.80,
    minimum_backend_requests: int = 5,
    error_rate_threshold: float = 0.50,
) -> list[ThreatFinding]:
    if minimum_total_requests < 1:
        raise ValueError(
            "minimum_total_requests must be at least 1"
        )

    if not 0 < imbalance_threshold <= 1:
        raise ValueError(
            "imbalance_threshold must be between 0 and 1"
        )

    if minimum_backend_requests < 1:
        raise ValueError(
            "minimum_backend_requests must be at least 1"
        )

    if not 0 < error_rate_threshold <= 1:
        raise ValueError(
            "error_rate_threshold must be between 0 and 1"
        )

    backend_events = defaultdict(list)

    for event in events:
        if event.source != "nginx":
            continue

        backend = event.backend or event.upstream

        if not backend:
            continue

        backend_events[backend].append(event)

    findings = []
    total_requests = sum(
        len(events)
        for events in backend_events.values()
    )

    if (
        total_requests >= minimum_total_requests
        and len(backend_events) >= 2
    ):
        for backend, related_events in backend_events.items():
            request_share = len(related_events) / total_requests

            if request_share < imbalance_threshold:
                continue

            findings.append(
                ThreatFinding(
                    title="Nginx Load Balancer Traffic Imbalance",
                    severity="medium",
                    description=(
                        f"Backend {backend!r} received "
                        f"{len(related_events)} of "
                        f"{total_requests} requests "
                        f"({request_share:.0%})."
                    ),
                    source="Nginx Load Balancer Detector",
                    hostname=related_events[0].virtual_host,
                    port=related_events[0].server_port,
                    recommendation=(
                        "Review upstream weights, health checks, and "
                        "load-balancing configuration."
                    ),
                )
            )

    for backend, related_events in backend_events.items():
        if len(related_events) < minimum_backend_requests:
            continue

        error_events = [
            event
            for event in related_events
            if (
                event.upstream_status is not None
                and event.upstream_status >= 500
            )
        ]

        error_rate = len(error_events) / len(related_events)

        if error_rate < error_rate_threshold:
            continue

        findings.append(
            ThreatFinding(
                title="Nginx Backend Error Rate Elevated",
                severity="high",
                description=(
                    f"Backend {backend!r} returned "
                    f"{len(error_events)} HTTP 5xx responses out of "
                    f"{len(related_events)} requests "
                    f"({error_rate:.0%})."
                ),
                source="Nginx Load Balancer Detector",
                hostname=related_events[0].virtual_host,
                port=related_events[0].server_port,
                recommendation=(
                    "Investigate backend health, remove unhealthy "
                    "nodes from the pool, and verify failover rules."
                ),
            )
        )

    return findings