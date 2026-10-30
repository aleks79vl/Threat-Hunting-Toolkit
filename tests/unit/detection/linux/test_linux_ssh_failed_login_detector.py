from src.detection.linux.ssh_failed_login_detector import (
    detect_ssh_failed_logins,
)
from src.models.linux_event import LinuxEvent


def test_detect_failed_ssh_login():
    events = [
        LinuxEvent(
            timestamp="Jul  7 08:15:01",
            hostname="ubuntu-server",
            service="ssh",
            process="sshd",
            pid="1425",
            user="admin",
            source_ip="203.0.113.50",
            port=49822,
            action="authentication",
            status="failed",
            message=(
                "Failed password for invalid user admin "
                "from 203.0.113.50 port 49822 ssh2"
            ),
        )
    ]

    findings = detect_ssh_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].title == "Failed SSH Login Detected"
    assert findings[0].severity == "medium"
    assert findings[0].source == "Linux Log Detection"
    assert findings[0].ip == "203.0.113.50"
    assert findings[0].hostname == "ubuntu-server"
    assert findings[0].port == 22


def test_ignore_successful_ssh_login():
    events = [
        LinuxEvent(
            service="ssh",
            action="authentication",
            status="success",
            source_ip="192.168.1.10",
        )
    ]

    findings = detect_ssh_failed_logins(events)

    assert findings == []


def test_ignore_non_ssh_failed_event():
    events = [
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="failed",
            source_ip="203.0.113.50",
        )
    ]

    findings = detect_ssh_failed_logins(events)

    assert findings == []


def test_failed_ssh_finding_preserves_normalized_utc_time():
    event = LinuxEvent(
        timestamp="Jul  7 10:00:01",
        timestamp_utc="2026-07-07T07:00:01+00:00",
        hostname="auth-host",
        service="ssh",
        process="sshd",
        user="admin",
        source_ip="203.0.113.50",
        action="authentication",
        status="failed",
    )

    findings = detect_ssh_failed_logins([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Failed SSH Login Detected"
    assert finding.first_seen == "2026-07-07T07:00:01+00:00"
    assert finding.last_seen == "2026-07-07T07:00:01+00:00"

    # Original event must remain unchanged.
    assert event.timestamp == "Jul  7 10:00:01"


def test_failed_ssh_finding_does_not_invent_unknown_time():
    event = LinuxEvent(
        timestamp="Jul  7 10:00:01",
        timestamp_utc=None,
        hostname="auth-host",
        service="ssh",
        process="sshd",
        user="admin",
        source_ip="203.0.113.50",
        action="authentication",
        status="failed",
    )

    findings = detect_ssh_failed_logins([event])

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
