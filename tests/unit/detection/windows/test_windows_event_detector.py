import pytest

from src.utils.event_utils import SecurityEvent

from src.parsers.windows_event_parser import parse_windows_events
from src.detection.windows.windows_event_detector import detect_windows_events


def test_detect_windows_events_returns_findings():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert len(findings) == 6


def test_detect_failed_logon():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert any(
        finding.title == "Windows Failed Logon Detected"
        for finding in findings
    )


def test_detect_user_created():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert any(
        finding.title == "Windows User Account Created"
        for finding in findings
    )


def test_detect_admin_group_change():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert any(
        finding.title == "User Added to Administrators Group"
        for finding in findings
    )


def test_detect_powershell_process():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert any(
        finding.title == "Suspicious PowerShell Process"
        for finding in findings
    )


def test_detect_audit_log_cleared():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    findings = detect_windows_events(events)

    assert any(
        finding.title == "Windows Audit Log Cleared"
        for finding in findings
    )


@pytest.mark.parametrize(
    "event_id, raw_event, expected_title",
    [
        (
            "4625",
            "Failed logon: winlogon.exe",
            "Windows Failed Logon Detected",
        ),
        (
            "4720",
            "User account created: net.exe",
            "Windows User Account Created",
        ),
        (
            "4732",
            "User added to Administrators group",
            "User Added to Administrators Group",
        ),
        (
            "4688",
            "Process created: powershell.exe",
            "Suspicious PowerShell Process",
        ),
        (
            "1102",
            "Audit log cleared: wevtutil.exe",
            "Windows Audit Log Cleared",
        ),
    ],
)


def test_windows_detector_preserves_event_time(
    event_id,
    raw_event,
    expected_title,
):
    event = SecurityEvent(
        timestamp="2026-07-16T13:00:00.123456789+03:00",
        source="Windows",
        event_type=event_id,
        src_ip="192.168.1.10",
        hostname="WIN-DC01",
        username="administrator",
        raw_event=raw_event,
    )

    findings = detect_windows_events([event])

    assert len(findings) == 1
    assert findings[0].title == expected_title

    expected_time = (
        "2026-07-16T10:00:00.123456789+00:00"
    )

    assert findings[0].first_seen == expected_time
    assert findings[0].last_seen == expected_time


def test_windows_detector_preserves_zulu_nanoseconds():
    event = SecurityEvent(
        timestamp="2026-07-16T09:00:00.000000001Z",
        source="Windows",
        event_type="4625",
        src_ip="203.0.113.15",
        hostname="WIN-DC01",
        username="administrator",
        raw_event="Failed logon: winlogon.exe",
    )

    findings = detect_windows_events([event])

    assert len(findings) == 1

    expected_time = (
        "2026-07-16T09:00:00.000000001+00:00"
    )

    assert findings[0].first_seen == expected_time
    assert findings[0].last_seen == expected_time


def test_windows_detector_does_not_invent_invalid_time():
    invalid_timestamps = [
        "",
        "invalid-timestamp",
        "2026-07-16T13:00:00",
        "NaN",
        "Infinity",
    ]

    for timestamp in invalid_timestamps:
        event = SecurityEvent(
            timestamp=timestamp,
            source="Windows",
            event_type="4720",
            src_ip="192.168.1.10",
            hostname="WIN-DC01",
            username="temp_admin",
            raw_event="User account created: net.exe",
        )

        findings = detect_windows_events([event])

        assert len(findings) == 1
        assert findings[0].first_seen is None
        assert findings[0].last_seen is None


def _create_windows_timezone_event(timestamp: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        source="Windows",
        event_type="4720",
        src_ip="192.168.1.10",
        hostname="WIN-DC01",
        username="temp_admin",
        raw_event="User account created: net.exe",
    )


def test_windows_detector_uses_configured_source_timezone():
    event = _create_windows_timezone_event(
        "2026-07-16 13:00:00.123456789"
    )

    findings = detect_windows_events(
        [event],
        source_timezone="Asia/Jerusalem",
    )

    assert len(findings) == 1
    assert findings[0].first_seen == (
        "2026-07-16T10:00:00.123456789+00:00"
    )
    assert findings[0].last_seen == (
        "2026-07-16T10:00:00.123456789+00:00"
    )

    # Original SecurityEvent must remain unchanged.
    assert event.timestamp == (
        "2026-07-16 13:00:00.123456789"
    )


def test_windows_detector_prefers_explicit_event_timezone():
    event = _create_windows_timezone_event(
        "2026-07-16T13:00:00.123456789+03:00"
    )

    findings = detect_windows_events(
        [event],
        source_timezone="America/New_York",
    )

    assert len(findings) == 1
    assert findings[0].first_seen == (
        "2026-07-16T10:00:00.123456789+00:00"
    )
    assert findings[0].last_seen == (
        "2026-07-16T10:00:00.123456789+00:00"
    )


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-11-01 01:30:00",
        "2026-03-08 02:30:00",
    ],
)
def test_windows_detector_rejects_ambiguous_or_missing_dst_time(
    timestamp,
):
    event = _create_windows_timezone_event(timestamp)

    findings = detect_windows_events(
        [event],
        source_timezone="America/New_York",
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
