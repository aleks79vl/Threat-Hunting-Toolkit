from src.detection.linux.telnet_detector import detect_telnet_activity
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


def _telnet_with_utc(
    timestamp_utc: str | None,
    source_ip: str = "198.51.100.25",
) -> LinuxEvent:
    event = create_telnet_event(source_ip=source_ip)
    event.timestamp_utc = timestamp_utc
    return event


def test_telnet_activity_preserves_normalized_utc_time():
    event = _telnet_with_utc(
        "2026-07-07T05:20:10.123456789+00:00"
    )

    findings = detect_telnet_activity([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Telnet Activity Detected"
    assert finding.first_seen == (
        "2026-07-07T05:20:10.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T05:20:10.123456789+00:00"
    )

    assert event.timestamp == "Jul  7 08:20:10"


def test_repeated_telnet_findings_preserve_group_time_range():
    timestamps = [
        "2026-07-07T07:04:00+00:00",
        "2026-07-07T07:00:00.100000001+00:00",
        "2026-07-07T07:03:00+00:00",
        "2026-07-07T07:00:00.1+00:00",
        "2026-07-07T07:02:00+00:00",
    ]

    events = [
        _telnet_with_utc(timestamp)
        for timestamp in timestamps
    ]

    # Unrelated SSH event must not change the range.
    events.append(
        LinuxEvent(
            service="ssh",
            source_ip="198.51.100.25",
            timestamp_utc="2026-07-07T05:00:00+00:00",
        )
    )

    findings = detect_telnet_activity(events)

    assert len(findings) == 2

    titles = {
        finding.title
        for finding in findings
    }

    assert titles == {
        "Telnet Activity Detected",
        "Repeated Telnet Login Attempts Detected",
    }

    for finding in findings:
        assert finding.first_seen == (
            "2026-07-07T07:00:00.1+00:00"
        )
        assert finding.last_seen == (
            "2026-07-07T07:04:00+00:00"
        )


def test_telnet_activity_tracks_sources_independently():
    events = [
        _telnet_with_utc(
            "2026-07-07T07:02:00+00:00",
            source_ip="198.51.100.25",
        ),
        _telnet_with_utc(
            "2026-07-07T08:01:00+00:00",
            source_ip="203.0.113.50",
        ),
        _telnet_with_utc(
            "2026-07-07T07:00:00+00:00",
            source_ip="198.51.100.25",
        ),
        _telnet_with_utc(
            "2026-07-07T08:00:00+00:00",
            source_ip="203.0.113.50",
        ),
    ]

    findings = detect_telnet_activity(events)

    assert len(findings) == 2

    findings_by_ip = {
        finding.ip: finding
        for finding in findings
    }

    assert findings_by_ip["198.51.100.25"].first_seen == (
        "2026-07-07T07:00:00+00:00"
    )
    assert findings_by_ip["198.51.100.25"].last_seen == (
        "2026-07-07T07:02:00+00:00"
    )

    assert findings_by_ip["203.0.113.50"].first_seen == (
        "2026-07-07T08:00:00+00:00"
    )
    assert findings_by_ip["203.0.113.50"].last_seen == (
        "2026-07-07T08:01:00+00:00"
    )


def test_telnet_findings_do_not_invent_incomplete_time_range():
    events = [
        _telnet_with_utc(
            f"2026-07-07T07:0{minute}:00+00:00"
        )
        for minute in range(4)
    ]

    events.append(_telnet_with_utc(None))

    findings = detect_telnet_activity(events)

    assert len(findings) == 2

    for finding in findings:
        assert finding.first_seen is None
        assert finding.last_seen is None
