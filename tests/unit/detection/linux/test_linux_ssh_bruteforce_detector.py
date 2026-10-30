from src.detection.linux.ssh_bruteforce_detector import (
    detect_ssh_bruteforce,
)
from src.models.linux_event import LinuxEvent

import pytest


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


def _failed_ssh_with_utc(
    timestamp_utc: str | None,
    source_ip: str = "203.0.113.50",
) -> LinuxEvent:
    event = create_failed_ssh_event(source_ip=source_ip)
    event.timestamp_utc = timestamp_utc
    return event


def test_ssh_bruteforce_preserves_group_time_range():
    timestamps = [
        "2026-07-07T07:04:00+00:00",
        "2026-07-07T07:00:00.100000001+00:00",
        "2026-07-07T07:03:00+00:00",
        "2026-07-07T07:00:00.1+00:00",
        "2026-07-07T07:02:00+00:00",
    ]

    events = [
        _failed_ssh_with_utc(timestamp)
        for timestamp in timestamps
    ]

    # A successful login from the same IP must not
    # affect the brute-force time range.
    events.append(
        LinuxEvent(
            service="ssh",
            action="authentication",
            status="success",
            source_ip="203.0.113.50",
            timestamp_utc="2026-07-07T06:00:00+00:00",
        )
    )

    # A failed attempt from another IP must not
    # affect this source's time range.
    events.append(
        _failed_ssh_with_utc(
            "2026-07-07T05:00:00+00:00",
            source_ip="198.51.100.25",
        )
    )

    findings = detect_ssh_bruteforce(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.ip == "203.0.113.50"
    assert finding.first_seen == (
        "2026-07-07T07:00:00.1+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:04:00+00:00"
    )


def test_ssh_bruteforce_tracks_each_source_independently():
    source_a = [
        _failed_ssh_with_utc(
            f"2026-07-07T07:0{minute}:00+00:00",
            source_ip="203.0.113.50",
        )
        for minute in range(5)
    ]

    source_b = [
        _failed_ssh_with_utc(
            f"2026-07-07T08:0{minute}:00+00:00",
            source_ip="198.51.100.25",
        )
        for minute in range(5)
    ]

    findings = detect_ssh_bruteforce(
        source_b + source_a
    )

    assert len(findings) == 2

    findings_by_ip = {
        finding.ip: finding
        for finding in findings
    }

    assert findings_by_ip["203.0.113.50"].first_seen == (
        "2026-07-07T07:00:00+00:00"
    )
    assert findings_by_ip["203.0.113.50"].last_seen == (
        "2026-07-07T07:04:00+00:00"
    )

    assert findings_by_ip["198.51.100.25"].first_seen == (
        "2026-07-07T08:00:00+00:00"
    )
    assert findings_by_ip["198.51.100.25"].last_seen == (
        "2026-07-07T08:04:00+00:00"
    )


@pytest.mark.parametrize(
    "unreliable_time",
    [
        None,
        "invalid timestamp",
    ],
)
def test_ssh_bruteforce_rejects_incomplete_time_range(
    unreliable_time,
):
    events = [
        _failed_ssh_with_utc(
            f"2026-07-07T07:0{minute}:00+00:00"
        )
        for minute in range(4)
    ]

    events.append(
        _failed_ssh_with_utc(unreliable_time)
    )

    findings = detect_ssh_bruteforce(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen is None
    assert finding.last_seen is None
