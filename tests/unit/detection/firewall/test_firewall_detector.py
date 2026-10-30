import pytest

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


@pytest.mark.parametrize(
    "action,src_ip,dst_port,expected_title",
    [
        (
            "DENY",
            "203.0.113.15",
            22,
            "Firewall Blocked Critical Port Access",
        ),
        (
            "ALLOW",
            "192.168.1.10",
            3389,
            "Firewall Allowed Critical Port Access",
        ),
        (
            "DENY",
            "203.0.113.44",
            80,
            "External Firewall Connection Attempt",
        ),
    ],
)


def test_firewall_finding_uses_configured_source_timezone(
    action,
    src_ip,
    dst_port,
    expected_title,
):
    event = SecurityEvent(
        timestamp="2026-07-16 13:00:00.123456789",
        source="Firewall",
        event_type=action,
        src_ip=src_ip,
        dst_ip="192.168.1.77",
        dst_port=dst_port,
        hostname="firewall-01",
    )

    findings = detect_firewall_events(
        [event],
        source_timezone="Asia/Jerusalem",
    )

    assert len(findings) == 1
    assert findings[0].title == expected_title

    expected_time = "2026-07-16T10:00:00.123456789+00:00"

    assert findings[0].first_seen == expected_time
    assert findings[0].last_seen == expected_time

    assert event.timestamp == "2026-07-16 13:00:00.123456789"


def test_firewall_finding_preserves_explicit_timestamp_timezone():
    event = SecurityEvent(
        timestamp="2026-07-16T13:00:00.123456789+03:00",
        source="Firewall",
        event_type="DENY",
        src_ip="203.0.113.15",
        dst_ip="192.168.1.77",
        dst_port=22,
        hostname="firewall-01",
    )

    findings = detect_firewall_events([event])

    assert len(findings) == 1

    expected_time = "2026-07-16T10:00:00.123456789+00:00"

    assert findings[0].first_seen == expected_time
    assert findings[0].last_seen == expected_time


def test_firewall_finding_does_not_invent_unknown_timezone():
    event = SecurityEvent(
        timestamp="2026-07-16 13:00:00",
        source="Firewall",
        event_type="DENY",
        src_ip="203.0.113.15",
        dst_ip="192.168.1.77",
        dst_port=22,
        hostname="firewall-01",
    )

    findings = detect_firewall_events([event])

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
