from src.detection.web.nginx_directory_traversal_detector import (
    detect_nginx_directory_traversal,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_event(path: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-18T18:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=403,
        virtual_host="portal.example.com",
        server_port=443,
    )


def test_detects_plain_directory_traversal():
    findings = detect_nginx_directory_traversal(
        [make_event("/../../etc/passwd")]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Nginx Directory Traversal Attempt Detected"
    )


def test_detects_double_encoded_directory_traversal():
    findings = detect_nginx_directory_traversal(
        [make_event("/%252e%252e%252fetc%252fpasswd")]
    )

    assert len(findings) == 1


def test_ignores_normal_path():
    findings = detect_nginx_directory_traversal(
        [make_event("/assets/images/logo.png")]
    )

    assert findings == []