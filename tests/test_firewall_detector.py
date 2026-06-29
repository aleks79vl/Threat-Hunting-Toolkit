from src.parsers.firewall_parser import parse_firewall_log
from src.detection.firewall_detector import (
    detect_firewall_events,
    is_external_ip,
)


def test_is_external_ip():
    assert is_external_ip("203.0.113.15") is True
    assert is_external_ip("198.51.100.23") is True
    assert is_external_ip("192.168.1.10") is False
    assert is_external_ip("10.0.0.5") is False


def test_detect_firewall_events_returns_findings():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    findings = detect_firewall_events(events)

    assert len(findings) >= 1


def test_detect_blocked_critical_port():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    findings = detect_firewall_events(events)

    assert any(
        finding.title == "Firewall Blocked Critical Port Access"
        for finding in findings
    )


def test_detect_allowed_critical_port():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    findings = detect_firewall_events(events)

    assert any(
        finding.title == "Firewall Allowed Critical Port Access"
        for finding in findings
    )


def test_detect_external_connection_attempt():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    findings = detect_firewall_events(events)

    assert any(
        finding.title == "External Firewall Connection Attempt"
        for finding in findings
    )
