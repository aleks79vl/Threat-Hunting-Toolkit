from src.detection.linux_ssh_bruteforce_detector import (
    detect_ssh_bruteforce,
)
from src.models.linux_event import LinuxEvent


def create_failed_ssh_event(
    source_ip: str = "203.0.113.50",
    hostname: str = "ubuntu-server",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 08:15:01",
        hostname=hostname,
        service="ssh",
        process="sshd",
        user="admin",
        source_ip=source_ip,
        port=49822,
        action="authentication",
        status="failed",
        message=(
            "Failed password for invalid user admin "
            f"from {source_ip} port 49822 ssh2"
        ),
    )


def test_detect_ssh_bruteforce_threshold_reached():
    events = [
        create_failed_ssh_event()
        for _ in range(5)
    ]

    findings = detect_ssh_bruteforce(events)

    assert len(findings) == 1
    assert findings[0].title == "SSH Brute Force Detected"
    assert findings[0].severity == "high"
    assert findings[0].ip == "203.0.113.50"
    assert findings[0].hostname == "ubuntu-server"
    assert findings[0].port == 22


def test_ignore_below_threshold_failed_logins():
    events = [
        create_failed_ssh_event()
        for _ in range(4)
    ]

    findings = detect_ssh_bruteforce(events)

    assert findings == []


def test_detect_multiple_bruteforce_sources():
    events = [
        create_failed_ssh_event(
            source_ip="203.0.113.50"
        )
        for _ in range(5)
    ]

    events.extend(
        [
            create_failed_ssh_event(
                source_ip="198.51.100.25"
            )
            for _ in range(5)
        ]
    )

    findings = detect_ssh_bruteforce(events)

    assert len(findings) == 2

    detected_ips = {
        finding.ip
        for finding in findings
    }

    assert "203.0.113.50" in detected_ips
    assert "198.51.100.25" in detected_ips


def test_ignore_successful_ssh_logins():
    events = [
        LinuxEvent(
            service="ssh",
            action="authentication",
            status="success",
            source_ip="203.0.113.50",
        )
        for _ in range(10)
    ]

    findings = detect_ssh_bruteforce(events)

    assert findings == []


def test_ignore_non_ssh_failed_events():
    events = [
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="failed",
            source_ip="203.0.113.50",
        )
        for _ in range(10)
    ]

    findings = detect_ssh_bruteforce(events)

    assert findings == []