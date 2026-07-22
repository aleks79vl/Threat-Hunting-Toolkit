from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


AUTOMATED_USER_AGENT_MARKERS = (
    "aiohttp",
    "curl",
    "go-http-client",
    "python-requests",
    "scrapy",
    "wget",
)


def _is_automated_user_agent(user_agent: str) -> bool:
    normalized_user_agent = user_agent.lower()

    return any(
        marker in normalized_user_agent
        for marker in AUTOMATED_USER_AGENT_MARKERS
    )


def detect_api_bot_and_scraping_activity(
    events: list[WebInfrastructureEvent],
    *,
    minimum_requests: int = 50,
    minimum_distinct_routes: int = 10,
    minimum_automated_requests: int = 20,
) -> list[ThreatFinding]:
    events_by_ip = defaultdict(list)

    for event in events:
        if event.source != "api_gateway":
            continue

        events_by_ip[event.client_ip].append(event)

    findings = []

    for client_ip, related_events in events_by_ip.items():
        routes = {
            event.metadata.get("route_template", "")
            or event.path
            for event in related_events
        }

        if (
            len(related_events) >= minimum_requests
            and len(routes) >= minimum_distinct_routes
        ):
            findings.append(
                ThreatFinding(
                    title="Potential API Scraping Activity",
                    severity="medium",
                    description=(
                        f"IP address {client_ip!r} sent "
                        f"{len(related_events)} requests across "
                        f"{len(routes)} distinct API routes."
                    ),
                    source="API Bot and Scraping Detector",
                    ip=client_ip,
                    hostname=related_events[0].virtual_host,
                    port=related_events[0].server_port,
                    recommendation=(
                        "Review client behaviour and apply route-based "
                        "rate limits, pagination limits, or bot controls."
                    ),
                )
            )

        automated_events = [
            event
            for event in related_events
            if _is_automated_user_agent(event.user_agent)
        ]

        if len(automated_events) < minimum_automated_requests:
            continue

        findings.append(
            ThreatFinding(
                title="Automated API Client Activity Detected",
                severity="medium",
                description=(
                    f"IP address {client_ip!r} sent "
                    f"{len(automated_events)} requests with "
                    "an automated-client User-Agent."
                ),
                source="API Bot and Scraping Detector",
                ip=client_ip,
                hostname=automated_events[0].virtual_host,
                port=automated_events[0].server_port,
                recommendation=(
                    "Confirm whether the automation is authorized and "
                    "apply bot detection or API-key quotas if needed."
                ),
            )
        )

    return findings