from src.detection.web.nginx_php_attack_detector import (
    detect_nginx_php_attacks,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_event(path: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T10:30:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=404,
        virtual_host="portal.example.com",
        server_port=443,
    )


def test_detects_php_source_disclosure_attempt():
    findings = detect_nginx_php_attacks(
        [make_event("/config.php.bak")]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential PHP Source Disclosure Attempt"
    )


def test_detects_suspicious_php_runtime_parameter():
    findings = detect_nginx_php_attacks(
        [make_event("/index.php?auto_prepend_file=php://input")]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential PHP Runtime Abuse Attempt"
    )


def test_ignores_normal_php_request():
    findings = detect_nginx_php_attacks(
        [make_event("/application/login.php")]
    )

    assert findings == []