from src.detection.linux.successful_login_after_failures_detector import (
    detect_successful_login_after_failures,
)
from src.models.linux_event import LinuxEvent


def create_ssh_event(
    status: str,
    source_ip: str = "203.0.113.50",
    user: str = "admin",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 08:15:01",
        hostname="ubuntu-server",
        service="ssh",
        process="sshd",
        user=user,
        source_ip=source_ip,
        port=49822,
        action="authentication",
        status=status,
        message=f"SSH authentication {status}",
    )


def test_detect_successful_login_after_failures():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1
    assert findings[0].title == "Successful Login After Failures Detected"
    assert findings[0].severity == "critical"
    assert findings[0].ip == "203.0.113.50"
    assert findings[0].hostname == "ubuntu-server"
    assert findings[0].port == 22


def test_ignore_successful_login_without_failures():
    events = [
        create_ssh_event("success", user="alex")
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def test_ignore_successful_login_below_threshold():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def test_detect_only_once_per_source_ip():
    events = [
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("failed"),
        create_ssh_event("success", user="alex"),
        create_ssh_event("success", user="root"),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1


def test_ignore_non_ssh_authentication_events():
    events = [
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="failed",
            source_ip="203.0.113.50",
        ),
        LinuxEvent(
            service="sudo",
            action="authentication",
            status="success",
            source_ip="203.0.113.50",
        ),
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def _ssh_event_with_utc(
    status: str,
    timestamp_utc: str | None,
    source_ip: str = "203.0.113.50",
) -> LinuxEvent:
    event = create_ssh_event(
        status=status,
        source_ip=source_ip,
    )
    event.timestamp_utc = timestamp_utc
    return event


def test_success_after_failures_uses_chronological_utc_order():
    events = [
        # Success is first in the input but last in time.
        _ssh_event_with_utc(
            "success",
            "2026-07-07T07:05:00+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:03:00+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:00:00.100000001+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:00:00.1+00:00",
        ),
        # Unrelated source must not affect the range.
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T05:00:00+00:00",
            source_ip="198.51.100.25",
        ),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.ip == "203.0.113.50"
    assert finding.first_seen == (
        "2026-07-07T07:00:00.1+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:05:00+00:00"
    )


def test_success_before_failures_is_not_detected_as_attack_chain():
    events = [
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:02:00+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:03:00+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:04:00+00:00",
        ),
        # Success is last in the input but occurred first.
        _ssh_event_with_utc(
            "success",
            "2026-07-07T07:01:00+00:00",
        ),
    ]

    findings = detect_successful_login_after_failures(events)

    assert findings == []


def test_success_after_failures_does_not_invent_incomplete_time_range():
    events = [
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:00:00+00:00",
        ),
        _ssh_event_with_utc(
            "failed",
            None,
        ),
        _ssh_event_with_utc(
            "failed",
            "2026-07-07T07:02:00+00:00",
        ),
        _ssh_event_with_utc(
            "success",
            "2026-07-07T07:03:00+00:00",
        ),
    ]

    findings = detect_successful_login_after_failures(events)

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
