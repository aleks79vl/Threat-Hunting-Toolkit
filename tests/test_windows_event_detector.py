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
