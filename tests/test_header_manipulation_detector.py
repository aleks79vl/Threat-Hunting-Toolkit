from src.detection.web.header_manipulation_detector import (
    detect_header_manipulation,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    method: str = "GET",
    request_headers: dict[str, str] | None = None,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method=method,
        path="/public",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        request_headers=request_headers or {},
    )


def test_detects_route_override_header():
    findings = detect_header_manipulation(
        [
            make_event(
                request_headers={
                    "X-Original-URL": "/admin/users"
                }
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Header-Based Route Override"
    )


def test_detects_http_method_override():
    findings = detect_header_manipulation(
        [
            make_event(
                method="POST",
                request_headers={
                    "X-HTTP-Method-Override": "DELETE"
                },
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "HTTP Method Override Header Detected"
    )


def test_detects_control_characters_in_header_value():
    findings = detect_header_manipulation(
        [
            make_event(
                request_headers={
                    "X-Request-Id": "request-1\r\nX-Admin: true"
                }
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Header Injection Detected"
    )


def test_ignores_regular_headers():
    findings = detect_header_manipulation(
        [
            make_event(
                request_headers={
                    "Accept": "application/json",
                    "X-Request-Id": "request-1",
                }
            )
        ]
    )

    assert findings == []