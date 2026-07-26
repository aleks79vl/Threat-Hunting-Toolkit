from src.detection.web.nginx_load_balancer_detector import (
    detect_nginx_load_balancer_anomalies,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    backend: str,
    upstream_status: int,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T12:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/products",
        status_code=upstream_status,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        upstream="api_backend",
        backend=backend,
        upstream_status=upstream_status,
    )


def test_detects_traffic_imbalance_between_backends():
    events = (
        [
            make_event(
                backend="10.0.1.10:8080",
                upstream_status=200,
            )
            for _ in range(8)
        ]
        + [
            make_event(
                backend="10.0.1.11:8080",
                upstream_status=200,
            )
            for _ in range(2)
        ]
    )

    findings = detect_nginx_load_balancer_anomalies(
        events,
        minimum_total_requests=10,
        imbalance_threshold=0.75,
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Nginx Load Balancer Traffic Imbalance"
    )


def test_detects_elevated_backend_error_rate():
    events = [
        make_event(
            backend="10.0.1.10:8080",
            upstream_status=status_code,
        )
        for status_code in [502, 502, 503, 200, 200]
    ]

    findings = detect_nginx_load_balancer_anomalies(
        events,
        minimum_total_requests=10,
        minimum_backend_requests=5,
        error_rate_threshold=0.50,
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Nginx Backend Error Rate Elevated"
    )
    assert findings[0].severity == "high"


def test_ignores_balanced_healthy_backends():
    events = (
        [
            make_event(
                backend="10.0.1.10:8080",
                upstream_status=200,
            )
            for _ in range(5)
        ]
        + [
            make_event(
                backend="10.0.1.11:8080",
                upstream_status=200,
            )
            for _ in range(5)
        ]
    )

    findings = detect_nginx_load_balancer_anomalies(
        events,
        minimum_total_requests=10,
        imbalance_threshold=0.75,
        minimum_backend_requests=5,
        error_rate_threshold=0.50,
    )

    assert findings == []