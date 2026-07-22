from src.detection.web.nginx_upstream_error_detector import (
    detect_nginx_upstream_errors,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_error_event(message: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-18T17:00:00Z",
        source="nginx_error",
        client_ip="198.51.100.23",
        method="GET",
        path="/api/users",
        status_code=0,
        virtual_host="api.example.com",
        upstream="http://10.0.1.15:8080/api/users",
        metadata={"message": message},
    )


def test_detects_nginx_upstream_timeout():
    findings = detect_nginx_upstream_errors(
        [
            make_error_event(
                "upstream timed out while reading response header "
                "from upstream"
            )
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Nginx Upstream Timeout Detected"


def test_detects_nginx_upstream_connection_failure():
    findings = detect_nginx_upstream_errors(
        [
            make_error_event(
                "connection refused while connecting to upstream"
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Nginx Upstream Connection Failure Detected"
    )


def test_ignores_error_without_upstream():
    event = make_error_event("upstream timed out")
    event.upstream = ""

    findings = detect_nginx_upstream_errors([event])

    assert findings == []