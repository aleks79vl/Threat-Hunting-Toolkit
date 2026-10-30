from src.detection.linux.service_manipulation_detector import (
    detect_linux_service_manipulation,
)
from src.models.linux_event import LinuxEvent

import pytest


def create_service_event(
    action: str,
    message: str,
    hostname: str = "ubuntu-server",
    process: str = "systemd",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 09:05:15",
        hostname=hostname,
        service="systemd",
        process=process,
        pid="1",
        message=message,
        action=action,
        status="success",
    )


def test_detect_service_stop():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert len(findings) == 1
    assert findings[0].title == "Linux Service Manipulation Detected"
    assert findings[0].severity == "medium"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_service_restart():
    events = [
        create_service_event(
            action="service_restart",
            message="Restarted networking.service.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert len(findings) == 1
    assert findings[0].title == "Linux Service Manipulation Detected"


def test_detect_repeated_service_manipulation():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
        create_service_event(
            action="service_restart",
            message="Restarted networking.service.",
        ),
        create_service_event(
            action="service_stop",
            message="Stopped SSH service.",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    assert any(
        finding.title
        == "Repeated Linux Service Manipulation Detected"
        for finding in findings
    )


def test_ignore_service_start():
    events = [
        create_service_event(
            action="service_start",
            message="Started OpenSSH server daemon.",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert findings == []


def test_ignore_unrelated_linux_event():
    events = [
        LinuxEvent(
            hostname="ubuntu-server",
            service="ssh",
            process="sshd",
            action="authentication",
            status="failed",
            message="Failed password for admin",
        )
    ]

    findings = detect_linux_service_manipulation(events)

    assert findings == []


def test_deduplicate_identical_service_events():
    events = [
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
        create_service_event(
            action="service_stop",
            message="Stopped Apache Web Server.",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    lifecycle_findings = [
        finding
        for finding in findings
        if finding.title == "Linux Service Manipulation Detected"
    ]

    assert len(lifecycle_findings) == 1


def test_ignore_empty_events():
    findings = detect_linux_service_manipulation([])

    assert findings == []


def _service_with_utc(
    action: str,
    message: str,
    timestamp_utc: str | None,
    hostname: str = "ubuntu-server",
    process: str = "systemd",
) -> LinuxEvent:
    event = create_service_event(
        action=action,
        message=message,
        hostname=hostname,
        process=process,
    )
    event.timestamp_utc = timestamp_utc
    return event


def test_service_manipulation_preserves_single_event_time():
    event = _service_with_utc(
        "service_stop",
        "Stopped Apache Web Server.",
        "2026-07-07T06:05:15.123456789+00:00",
    )

    findings = detect_linux_service_manipulation([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Linux Service Manipulation Detected"
    assert finding.first_seen == (
        "2026-07-07T06:05:15.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:05:15.123456789+00:00"
    )

    assert event.timestamp == "Jul  7 09:05:15"


def test_service_deduplicated_finding_preserves_time_range():
    message = "Stopped Apache Web Server."

    events = [
        _service_with_utc(
            "service_stop",
            message,
            "2026-07-07T07:04:00+00:00",
        ),
        _service_with_utc(
            "service_stop",
            message,
            "2026-07-07T07:00:00.100000001+00:00",
        ),
        _service_with_utc(
            "service_stop",
            message,
            "2026-07-07T07:00:00.1+00:00",
        ),
        _service_with_utc(
            "service_stop",
            message,
            "2026-07-07T05:00:00+00:00",
            hostname="other-server",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    lifecycle_findings = [
        finding
        for finding in findings
        if finding.title == "Linux Service Manipulation Detected"
    ]

    assert len(lifecycle_findings) == 2

    findings_by_host = {
        finding.hostname: finding
        for finding in lifecycle_findings
    }

    main_finding = findings_by_host["ubuntu-server"]

    assert main_finding.first_seen == (
        "2026-07-07T07:00:00.1+00:00"
    )
    assert main_finding.last_seen == (
        "2026-07-07T07:04:00+00:00"
    )

    other_finding = findings_by_host["other-server"]

    assert other_finding.first_seen == (
        "2026-07-07T05:00:00+00:00"
    )
    assert other_finding.last_seen == (
        "2026-07-07T05:00:00+00:00"
    )


def test_repeated_service_manipulation_preserves_process_time_range():
    events = [
        _service_with_utc(
            "service_stop",
            "Stopped Apache Web Server.",
            "2026-07-07T07:04:00+00:00",
        ),
        _service_with_utc(
            "service_restart",
            "Restarted networking.service.",
            "2026-07-07T07:02:00+00:00",
        ),
        _service_with_utc(
            "service_stop",
            "Stopped Apache Web Server.",
            "2026-07-07T07:00:00.1+00:00",
        ),
        # Unmonitored service_start must not affect the range.
        _service_with_utc(
            "service_start",
            "Started networking.service.",
            "2026-07-07T04:00:00+00:00",
        ),
        # Different process on the same host.
        _service_with_utc(
            "service_stop",
            "Stopped another service.",
            "2026-07-07T05:00:00+00:00",
            process="service-manager",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    repeated_findings = [
        finding
        for finding in findings
        if finding.title == (
            "Repeated Linux Service Manipulation Detected"
        )
    ]

    assert len(repeated_findings) == 1

    finding = repeated_findings[0]

    assert finding.severity == "high"
    assert finding.hostname == "ubuntu-server"
    assert finding.first_seen == (
        "2026-07-07T07:00:00.1+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:04:00+00:00"
    )


@pytest.mark.parametrize(
    "unreliable_time",
    [None, "invalid timestamp"],
)


def test_service_findings_reject_incomplete_time_ranges(
    unreliable_time,
):
    events = [
        _service_with_utc(
            "service_stop",
            "Stopped Apache Web Server.",
            "2026-07-07T07:00:00+00:00",
        ),
        _service_with_utc(
            "service_stop",
            "Stopped Apache Web Server.",
            unreliable_time,
        ),
        _service_with_utc(
            "service_restart",
            "Restarted networking.service.",
            "2026-07-07T07:02:00+00:00",
        ),
    ]

    findings = detect_linux_service_manipulation(events)

    assert len(findings) == 3

    repeated = next(
        finding
        for finding in findings
        if finding.title == (
            "Repeated Linux Service Manipulation Detected"
        )
    )

    assert repeated.first_seen is None
    assert repeated.last_seen is None

    lifecycle_findings = [
        finding
        for finding in findings
        if finding.title == "Linux Service Manipulation Detected"
    ]

    assert len(lifecycle_findings) == 2

    apache_finding = next(
        finding
        for finding in lifecycle_findings
        if "Apache" in finding.description
    )

    assert apache_finding.first_seen is None
    assert apache_finding.last_seen is None

    networking_finding = next(
        finding
        for finding in lifecycle_findings
        if "networking" in finding.description
    )

    assert networking_finding.first_seen == (
        "2026-07-07T07:02:00+00:00"
    )
    assert networking_finding.last_seen == (
        "2026-07-07T07:02:00+00:00"
    )
