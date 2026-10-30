import pytest

from src.utils.event_utils import SecurityEvent
from src.parsers.web_log_parser import parse_web_log
from src.detection.web.web_attack_detector import detect_web_attacks


def test_detect_web_attacks_returns_findings():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert len(findings) >= 7


def test_detect_sql_injection():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "SQL Injection Attempt Detected"
        for finding in findings
    )


def test_detect_xss():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "XSS Attempt Detected"
        for finding in findings
    )


def test_detect_directory_traversal():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Directory Traversal Attempt Detected"
        for finding in findings
    )


def test_detect_suspicious_user_agent():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Suspicious Web User-Agent Detected"
        for finding in findings
    )


def test_detect_admin_brute_force():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Possible Admin Brute Force Detected"
        for finding in findings
    )


def test_detect_web_enumeration():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Possible Web Enumeration Detected"
        for finding in findings
    )


@pytest.mark.parametrize(
    "raw_event,expected_title,timestamp",
    [
        (
            "GET /?id=1 UNION SELECT HTTP/1.1",
            "SQL Injection Attempt Detected",
            "29/Jun/2026:12:00:01.123456789 +0300",
        ),
        (
            "GET /?x=<script> HTTP/1.1",
            "XSS Attempt Detected",
            "29/Jun/2026:09:00:01.123456789 +0000",
        ),
        (
            "GET /../../etc/passwd HTTP/1.1",
            "Directory Traversal Attempt Detected",
            "29/Jun/2026:04:00:01.123456789 -0500",
        ),
        (
            "GET / HTTP/1.1 User-Agent: nikto",
            "Suspicious Web User-Agent Detected",
            "29/Jun/2026:12:00:01.123456789 +0300",
        ),
    ],
)


def test_web_single_event_finding_preserves_apache_timestamp(
    raw_event,
    expected_title,
    timestamp,
):
    event = SecurityEvent(
        timestamp=timestamp,
        source="Web",
        event_type="GET",
        src_ip="203.0.113.15",
        dst_ip="192.168.1.77",
        dst_port=80,
        hostname="web-server",
        raw_event=raw_event,
    )

    findings = detect_web_attacks([event])

    matching = [
        finding
        for finding in findings
        if finding.title == expected_title
    ]

    assert len(matching) == 1

    expected_time = (
        "2026-06-29T09:00:01.123456789+00:00"
    )

    assert matching[0].first_seen == expected_time
    assert matching[0].last_seen == expected_time

    # Исходное событие не должно изменяться.
    assert event.timestamp == timestamp


def _make_web_time_event(
    timestamp: str,
    raw_event: str,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        source="Web",
        event_type="GET",
        src_ip="203.0.113.15",
        dst_ip="192.168.1.77",
        dst_port=80,
        hostname="web-server",
        raw_event=raw_event,
    )


@pytest.mark.parametrize(
    "trigger,expected_title,timestamps,expected_last",
    [
        (
            'POST /admin/login.php HTTP/1.1" 401 512',
            "Possible Admin Brute Force Detected",
            [
                "29/Jun/2026:09:05:00.123456789 +0000",
                "29/Jun/2026:12:00:00.123456789 +0300",
            ],
            "2026-06-29T09:05:00.123456789+00:00",
        ),
        (
            'GET /missing HTTP/1.1" 404 100',
            "Possible Web Enumeration Detected",
            [
                "29/Jun/2026:09:07:00.123456789 +0000",
                "29/Jun/2026:12:00:00.123456789 +0300",
                "29/Jun/2026:04:03:00.123456789 -0500",
            ],
            "2026-06-29T09:07:00.123456789+00:00",
        ),
    ],
)
def test_web_grouped_finding_preserves_event_time_range(
    trigger,
    expected_title,
    timestamps,
    expected_last,
):
    events = [
        _make_web_time_event(timestamp, trigger)
        for timestamp in timestamps
    ]

    # Same IP, but this request did not participate
    # in the grouped detection.
    events.append(
        _make_web_time_event(
            "29/Jun/2026:08:00:00 +0000",
            'GET / HTTP/1.1" 200 100',
        )
    )

    findings = detect_web_attacks(events)

    matching = [
        finding
        for finding in findings
        if finding.title == expected_title
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-06-29T09:00:00.123456789+00:00"
    )
    assert matching[0].last_seen == expected_last


@pytest.mark.parametrize(
    "trigger,expected_title,required_count",
    [
        (
            'POST /admin/login.php HTTP/1.1" 401 512',
            "Possible Admin Brute Force Detected",
            2,
        ),
        (
            'GET /missing HTTP/1.1" 404 100',
            "Possible Web Enumeration Detected",
            3,
        ),
    ],
)


def test_web_grouped_finding_rejects_incomplete_time_range(
    trigger,
    expected_title,
    required_count,
):
    events = [
        _make_web_time_event(
            "29/Jun/2026:09:00:00 +0000",
            trigger,
        ),
        _make_web_time_event(
            "invalid timestamp",
            trigger,
        ),
    ]

    if required_count == 3:
        events.append(
            _make_web_time_event(
                "29/Jun/2026:09:02:00 +0000",
                trigger,
            )
        )

    findings = detect_web_attacks(events)

    matching = [
        finding
        for finding in findings
        if finding.title == expected_title
    ]

    assert len(matching) == 1
    assert matching[0].first_seen is None
    assert matching[0].last_seen is None
