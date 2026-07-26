from src.detection.web.api_bot_scraping_detector import (
    detect_api_bot_and_scraping_activity,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    route_template: str,
    user_agent: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T09:00:00Z",
        source="api_gateway",
        client_ip=client_ip,
        method="GET",
        path=route_template,
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        user_agent=user_agent,
        metadata={
            "route_template": route_template,
        },
    )


def test_detects_high_volume_access_across_api_routes():
    events = [
        make_event(
            client_ip="203.0.113.44",
            route_template=f"/v1/products/{number}",
            user_agent="ExampleBrowser/1.0",
        )
        for number in range(3)
    ]

    findings = detect_api_bot_and_scraping_activity(
        events,
        minimum_requests=3,
        minimum_distinct_routes=3,
    )

    assert len(findings) == 1
    assert findings[0].title == "Potential API Scraping Activity"


def test_detects_repeated_automated_client_activity():
    events = [
        make_event(
            client_ip="203.0.113.44",
            route_template="/v1/products",
            user_agent="python-requests/2.32.0",
        )
        for _ in range(3)
    ]

    findings = detect_api_bot_and_scraping_activity(
        events,
        minimum_requests=10,
        minimum_automated_requests=3,
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Automated API Client Activity Detected"
    )


def test_ignores_normal_api_usage():
    findings = detect_api_bot_and_scraping_activity(
        [
            make_event(
                client_ip="203.0.113.44",
                route_template="/v1/profile",
                user_agent="ExampleMobileApp/2.4",
            ),
            make_event(
                client_ip="203.0.113.44",
                route_template="/v1/orders",
                user_agent="ExampleMobileApp/2.4",
            ),
        ],
        minimum_requests=3,
        minimum_distinct_routes=3,
        minimum_automated_requests=3,
    )

    assert findings == []