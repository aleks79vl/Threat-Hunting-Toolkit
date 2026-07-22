from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_api_resource_consumption(
    events: list[WebInfrastructureEvent],
    *,
    minimum_requests: int = 100,
    minimum_average_response_time_ms: float = 1000.0,
) -> list[ThreatFinding]:
    if minimum_requests < 1:
        raise ValueError(
            "minimum_requests must be at least 1"
        )

    usage_by_ip_and_route = defaultdict(list)

    for event in events:
        if event.source != "api_gateway":
            continue

        route = event.metadata.get(
            "route_template",
            "",
        ) or event.path

        usage_by_ip_and_route[
            (event.client_ip, route)
        ].append(event)

    findings = []

    for (
        client_ip,
        route,
    ), related_events in usage_by_ip_and_route.items():
        request_count = len(related_events)

        if request_count >= minimum_requests:
            findings.append(
                ThreatFinding(
                    title="High API Request Volume Detected",
                    severity="medium",
                    description=(
                        f"IP address {client_ip!r} sent "
                        f"{request_count} requests to API route "
                        f"{route!r}."
                    ),
                    source="API Resource Consumption Detector",
                    ip=client_ip,
                    hostname=related_events[0].virtual_host,
                    port=related_events[0].server_port,
                    recommendation=(
                        "Review rate limits and apply request quotas "
                        "for this client and API route."
                    ),
                )
            )

        response_times = [
            event.response_time_ms
            for event in related_events
            if event.response_time_ms is not None
        ]

        if not response_times:
            continue

        average_response_time_ms = (
            sum(response_times) / len(response_times)
        )

        if (
            average_response_time_ms
            < minimum_average_response_time_ms
        ):
            continue

        findings.append(
            ThreatFinding(
                title="Slow API Route Under Repeated Use",
                severity="medium",
                description=(
                    f"IP address {client_ip!r} generated "
                    f"{request_count} requests to {route!r} with "
                    "an average response time of "
                    f"{average_response_time_ms:.1f} ms."
                ),
                source="API Resource Consumption Detector",
                ip=client_ip,
                hostname=related_events[0].virtual_host,
                port=related_events[0].server_port,
                recommendation=(
                    "Investigate expensive API operations and apply "
                    "timeouts, caching, pagination, or request quotas."
                ),
            )
        )

    return findings