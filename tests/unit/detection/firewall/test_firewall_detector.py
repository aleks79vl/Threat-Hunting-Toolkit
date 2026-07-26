from src.parsers.firewall_parser import parse_firewall_log
from src.detection.firewall.firewall_detector import (
    detect_firewall_events,
    is_external_ip,
)
from src.utils.event_utils import SecurityEvent

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

def test_firewall_finding_uses_source_ip_for_correlation():
    event = SecurityEvent(
        timestamp="2026-07-22T14:00:00Z",
        source="firewall",
        event_type="DENY",
        src_ip="203.0.113.44",
        dst_ip="10.0.0.10",
        dst_port=22,
        hostname="gateway.example.com",
    )

    findings = detect_firewall_events([event])

    assert len(findings) == 1
    assert findings[0].ip == "203.0.113.44"
