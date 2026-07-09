from src.detection.linux_service_manipulation_detector import (
    detect_linux_service_manipulation,
)
from src.models.linux_event import LinuxEvent


def create_service_event(
    action: str,
    message: str,
    hostname: str = "ubuntu-server",
    process: str = "systemd",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 09:05:15",
        hostname=hostname,
        service="systemd",
        process=process,
        pid="1",
        message=message,
        action=action,
        status="success",
    )


def test_detect_service_stop():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert len(findings) == 1
    assert findings[0].title == "Linux Service Manipulation Detected"
    assert findings[0].severity == "medium"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_service_restart():
    events = [
        create_service_event(
            action="service_restart",
            message="Restarted networking.service.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert len(findings) == 1
    assert findings[0].title == "Linux Service Manipulation Detected"


def test_detect_repeated_service_manipulation():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
        create_service_event(
            action="service_restart",
            message="Restarted networking.service.",
        ),
        create_service_event(
            action="service_stop",
            message="Stopped SSH service.",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    assert any(
        finding.title
        == "Repeated Linux Service Manipulation Detected"
        for finding in findings
    )


def test_ignore_service_start():
    events = [
        create_service_event(
            action="service_start",
            message="Started OpenSSH server daemon.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert findings == []


def test_ignore_unrelated_linux_event():
    events = [
        LinuxEvent(
            hostname="ubuntu-server",
            service="ssh",
            process="sshd",
            action="authentication",
            status="failed",
            message="Failed password for admin",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert findings == []


def test_deduplicate_identical_service_events():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    lifecycle_findings = [
        finding
        for finding in findings
        if finding.title == "Linux Service Manipulation Detected"
    ]

    assert len(lifecycle_findings) == 1


def test_ignore_empty_events():
    findings = detect_linux_service_manipulation([])

    assert findings == []