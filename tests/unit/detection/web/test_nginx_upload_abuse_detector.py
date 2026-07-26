from src.detection.web.nginx_upload_abuse_detector import (
    detect_nginx_upload_abuse,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_event(
    method: str,
    path: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T10:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method=method,
        path=path,
        status_code=201,
        virtual_host="portal.example.com",
        server_port=443,
    )


def test_detects_executable_file_upload():
    findings = detect_nginx_upload_abuse(
        [make_event("POST", "/uploads/profile.phtml")]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Malicious File Upload Detected"
    )
    assert findings[0].severity == "high"


def test_ignores_normal_image_upload():
    findings = detect_nginx_upload_abuse(
        [make_event("POST", "/uploads/avatar.png")]
    )

    assert findings == []


def test_ignores_executable_file_outside_upload_path():
    findings = detect_nginx_upload_abuse(
        [make_event("GET", "/application/index.php")]
    )

    assert findings == []