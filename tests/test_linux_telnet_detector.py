from src.detection.linux_telnet_detector import detect_telnet_activity
from src.models.linux_event import LinuxEvent


def create_telnet_event(
    source_ip: str = "198.51.100.25",
    hostname: str = "legacy-server",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 08:20:10",
        hostname=hostname,
        service="telnet",
        process="in.telnetd",
        pid="2201",
        message="connect from 198.51.100.25",
        source_ip=source_ip,
        port=23,
        action="connection",
        status="success",
    )


def test_detect_telnet_activity():
    events = [
        create_telnet_event()
    ]

    findings = detect_telnet_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "Telnet Activity Detected"
    assert findings[0].severity == "medium"
    assert findings[0].ip == "198.51.100.25"
    assert findings[0].hostname == "legacy-server"
    assert findings[0].port == 23


def test_detect_repeated_telnet_attempts():
    events = [
        create_telnet_event(
            source_ip="198.51.100.25"
        )
        for _ in range(5)
    ]

    findings = detect_telnet_activity(events)

    assert any(
        finding.title == "Repeated Telnet Login Attempts Detected"
        for finding in findings
    )


def test_single_telnet_source_creates_one_activity_finding():
    events = [
        create_telnet_event(
            source_ip="198.51.100.25"
        ),
        create_telnet_event(
            source_ip="198.51.100.25"
        ),
        create_telnet_event(
            source_ip="198.51.100.25"
        ),
    ]

    findings = detect_telnet_activity(events)

    activity_findings = [
        finding
        for finding in findings
        if finding.title == "Telnet Activity Detected"
    ]

    assert len(activity_findings) == 1


def test_ignore_non_telnet_events():
    events = [
        LinuxEvent(
            service="ssh",
            source_ip="198.51.100.25",
            action="authentication",
            status="failed",
        )
    ]

    findings = detect_telnet_activity(events)

    assert findings == []


def test_ignore_empty_events():
    findings = detect_telnet_activity([])

    assert findings == []