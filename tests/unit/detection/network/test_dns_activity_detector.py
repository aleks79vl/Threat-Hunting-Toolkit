from src.detection.network.dns_activity_detector import (
    detect_suspicious_dns_activity,
)
from src.models.network_event import NetworkEvent
from datetime import datetime, timezone


def create_dns_event(
    dns_query: str,
    src_ip: str = "10.0.0.3",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip="10.0.0.138",
        protocol="DNS",
        src_port="57772",
        dst_port="53",
        dns_query=dns_query,
        http_host="",
        http_uri="",
    )


def test_detect_repeated_dns_queries():
    events = [
        create_dns_event("example.com")
        for _ in range(10)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Repeated DNS Query Activity Detected"
        for finding in findings
    )


def test_detect_long_dns_query():
    long_query = (
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        ".example.com"
    )

    events = [
        create_dns_event(long_query)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Long DNS Query Detected"
        for finding in findings
    )


def test_detect_suspicious_dns_tld():
    events = [
        create_dns_event("malicious-example.xyz")
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Suspicious DNS TLD Detected"
        for finding in findings
    )


def test_detect_high_dns_query_volume():
    events = [
        create_dns_event(
            f"domain-{index}.com",
            src_ip="10.0.0.50",
        )
        for index in range(100)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "High DNS Query Volume Detected"
        and finding.ip == "10.0.0.50"
        for finding in findings
    )


def test_ignore_normal_dns_activity():
    events = [
        create_dns_event("google.com"),
        create_dns_event("example.com"),
        create_dns_event("walla.co.il"),
    ]

    findings = detect_suspicious_dns_activity(events)

    assert findings == []


def test_ignore_events_without_dns_queries():
    events = [
        NetworkEvent(
            timestamp="1385452028.038401000",
            src_ip="10.0.0.3",
            dst_ip="173.194.112.47",
            protocol="TCP",
            src_port="45822",
            dst_port="443",
        )
    ]

    findings = detect_suspicious_dns_activity(events)

    assert findings == []


def _dns_epoch(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_dns_query_findings_preserve_packet_time_range():
    query = "a" * 55 + ".xyz"

    events = [
        create_dns_event(query, src_ip="10.0.0.20")
        for _ in range(10)
    ]

    for event in events:
        event.timestamp = _dns_epoch(9, 3)

    events[0].timestamp = _dns_epoch(
        9, 0, "123456789"
    )
    events[-1].timestamp = _dns_epoch(
        9, 5, "987654321"
    )

    unrelated = create_dns_event(
        "other.xyz",
        src_ip="10.0.0.21",
    )
    unrelated.timestamp = _dns_epoch(7, 0)

    findings = detect_suspicious_dns_activity([
        events[-1],
        unrelated,
        *events[1:-1],
        events[0],
    ])

    expected_titles = {
        "Repeated DNS Query Activity Detected",
        "Long DNS Query Detected",
        "Suspicious DNS TLD Detected",
    }

    for title in expected_titles:
        matching = [
            finding
            for finding in findings
            if finding.title == title
            and query in finding.description
        ]

        assert len(matching) == 1

        assert matching[0].first_seen == (
            "2026-07-16T09:00:00.123456789+00:00"
        )
        assert matching[0].last_seen == (
            "2026-07-16T09:05:00.987654321+00:00"
        )

    unrelated_findings = [
        finding
        for finding in findings
        if finding.title == "Suspicious DNS TLD Detected"
        and "other.xyz" in finding.description
    ]

    assert len(unrelated_findings) == 1
    assert unrelated_findings[0].first_seen == (
        "2026-07-16T07:00:00+00:00"
    )
    assert unrelated_findings[0].last_seen == (
        "2026-07-16T07:00:00+00:00"
    )


def test_high_dns_volume_preserves_source_time_range():
    events = [
        create_dns_event(
            f"domain-{index}.com",
            src_ip="10.0.0.50",
        )
        for index in range(100)
    ]

    for event in events:
        event.timestamp = _dns_epoch(9, 3)

    events[0].timestamp = _dns_epoch(9, 0)
    events[-1].timestamp = _dns_epoch(9, 7)

    unrelated = create_dns_event(
        "unrelated.com",
        src_ip="10.0.0.51",
    )
    unrelated.timestamp = _dns_epoch(6, 0)

    findings = detect_suspicious_dns_activity([
        events[-1],
        unrelated,
        *events[1:-1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "High DNS Query Volume Detected"
        and finding.ip == "10.0.0.50"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T09:07:00+00:00"
    )


def test_dns_invalid_timestamps_are_not_invented():
    query = "b" * 55 + ".com"

    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        valid_event = create_dns_event(query)
        valid_event.timestamp = _dns_epoch(9, 0)

        invalid_event = create_dns_event(query)
        invalid_event.timestamp = invalid_timestamp

        for events in (
            [valid_event, invalid_event],
            [invalid_event, valid_event],
        ):
            findings = detect_suspicious_dns_activity(
                events
            )

            matching = [
                finding
                for finding in findings
                if finding.title == "Long DNS Query Detected"
            ]

            assert len(matching) == 1
            assert matching[0].first_seen is None
            assert matching[0].last_seen is None
