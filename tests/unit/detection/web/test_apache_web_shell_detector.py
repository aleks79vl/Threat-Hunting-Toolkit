from src.detection.web.apache_web_shell_detector import (
    detect_apache_web_shells,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def make_event(path: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-18T15:00:00Z",
        source="apache",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=200,
        virtual_host="portal.example.com",
        server_port=443,
    )


def test_detects_script_in_writable_web_path():
    findings = detect_apache_web_shells(
        [make_event("/uploads/invoice.phtml")]
    )

    assert len(findings) == 1
    assert findings[0].title == "Potential Apache Web Shell Access"
    assert findings[0].severity == "high"


def test_detects_suspicious_command_parameter():
    findings = detect_apache_web_shells(
        [make_event("/index.php?cmd=whoami")]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Web Shell Command Execution"
    )
    assert findings[0].severity == "critical"


def test_ignores_normal_php_endpoint():
    findings = detect_apache_web_shells(
        [make_event("/application/login.php")]
    )

    assert findings == []