from src.detection.web.nginx_http_method_detector import (
    detect_nginx_http_method_abuse,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_event(method: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-18T17:30:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method=method,
        path="/api/users",
        status_code=200,
        virtual_host="api.example.com",
        server_port=443,
    )


def test_detects_high_risk_trace_method():
    findings = detect_nginx_http_method_abuse(
        [make_event("TRACE")]
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].title == "High-Risk HTTP Method Detected"


def test_detects_modification_method():
    findings = detect_nginx_http_method_abuse(
        [make_event("DELETE")]
    )

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert (
        findings[0].title
        == "Potential HTTP Method Abuse Detected"
    )


def test_ignores_standard_get_method():
    findings = detect_nginx_http_method_abuse(
        [make_event("GET")]
    )

    assert findings == []