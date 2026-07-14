from src.detection.linux.successful_login_after_failures_detector import (
    detect_successful_login_after_failures,
)
from src.models.linux_event import LinuxEvent


def create_ssh_event(
    status: str,
    source_ip: str = "203.0.113.50",
    user: str = "admin",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 08:15:01",
        hostname="ubuntu-server",
        service="ssh",
        process="sshd",
        user=user,
        source_ip=source_ip,
        port=49822,
        action="authentication",
        status=status,
        message=f"SSH authentication {status}",
    )


def test_detect_successful_login_after_failures():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1
    assert findings[0].title == "Successful Login After Failures Detected"
    assert findings[0].severity == "critical"
    assert findings[0].ip == "203.0.113.50"
    assert findings[0].hostname == "ubuntu-server"
    assert findings[0].port == 22


def test_ignore_successful_login_without_failures():
    events = [
        create_ssh_event("success", user="alex")
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def test_ignore_successful_login_below_threshold():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def test_detect_only_once_per_source_ip():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
        create_ssh_event("success", user="root"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1


def test_ignore_non_ssh_authentication_events():
    events = [
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="failed",
            source_ip="203.0.113.50",
        ),
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="success",
            source_ip="203.0.113.50",
        ),
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []