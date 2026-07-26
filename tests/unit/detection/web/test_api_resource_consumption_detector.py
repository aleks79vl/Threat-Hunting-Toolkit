from src.detection.web.api_resource_consumption_detector import (
    detect_api_resource_consumption,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    route_template: str,
    response_time_ms: float,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T08:00:00Z",
        source="api_gateway",
        client_ip=client_ip,
        method="GET",
        path="/v1/search",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        response_time_ms=response_time_ms,
        metadata={
            "route_template": route_template,
        },
    )


def test_detects_high_request_volume_for_api_route():
    events = [
        make_event(
            client_ip="203.0.113.44",
            route_template="/v1/search",
            response_time_ms=20.0,
        )
        for _ in range(3)
    ]

    findings = detect_api_resource_consumption(
        events,
        minimum_requests=3,
    )

    assert len(findings) == 1
    assert findings[0].title == "High API Request Volume Detected"


def test_detects_repeated_slow_api_requests():
    events = [
        make_event(
            client_ip="203.0.113.44",
            route_template="/v1/reports/export",
            response_time_ms=1500.0,
        )
        for _ in range(3)
    ]

    findings = detect_api_resource_consumption(
        events,
        minimum_requests=10,
        minimum_average_response_time_ms=1000.0,
    )

    assert len(findings) == 1
    assert findings[0].title == "Slow API Route Under Repeated Use"


def test_ignores_normal_api_usage():
    findings = detect_api_resource_consumption(
        [
            make_event(
                client_ip="203.0.113.44",
                route_template="/v1/profile",
                response_time_ms=25.0,
            ),
            make_event(
                client_ip="203.0.113.44",
                route_template="/v1/profile",
                response_time_ms=30.0,
            ),
        ],
        minimum_requests=3,
        minimum_average_response_time_ms=1000.0,
    )

    assert findings == []