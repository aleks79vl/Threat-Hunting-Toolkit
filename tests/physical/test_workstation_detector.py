from datetime import datetime, timedelta, timezone

from src.detection.physical.workstation_detector import (
    detect_workstation_activity,
)
from src.models.physical_event import PhysicalEvent


BASE_TIME = datetime(2026, 7, 15, 12, 0, 0)


def create_event(
    event_type: str,
    *,
    minutes: int = 0,
    hostname: str = "WORKSTATION-01",
    user: str = "alex",
    previous_user: str | None = None,
    device_type: str = "workstation",
    device_name: str = "Corporate Workstation",
    device_id: str = "WS-001",
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        event_type=event_type,
        device_type=device_type,
        device_name=device_name,
        device_id=device_id,
        hostname=hostname,
        user=user,
        previous_user=previous_user,
    )


def test_remote_logon_detection():
    findings = detect_workstation_activity(
        [create_event("remote_logon")]
    )

    assert any(
        finding.title == "Remote Workstation Logon Detected"
        for finding in findings
    )


def test_console_logon_outside_working_hours():
    event = PhysicalEvent(
        timestamp=datetime(2026, 7, 15, 2, 30, 0),
        event_type="console_logon",
        device_type="workstation",
        device_name="Corporate Workstation",
        device_id="WS-001",
        hostname="WORKSTATION-01",
        user="alex",
    )

    findings = detect_workstation_activity([event])

    assert any(
        finding.title == "Console Logon Outside Working Hours"
        for finding in findings
    )


def test_unlock_after_usb_connection():
    events = [
        create_event(
            "usb_insert",
            device_type="USB",
            device_name="Unknown USB Device",
            device_id="USB-001",
        ),
        create_event(
            "workstation_unlock",
            minutes=2,
        ),
    ]

    findings = detect_workstation_activity(events)

    assert any(
        finding.title
        == "Workstation Unlocked After Physical Device Connection"
        for finding in findings
    )


def test_session_user_change():
    event = create_event(
        "session_switch",
        user="admin",
        previous_user="alex",
    )

    findings = detect_workstation_activity([event])

    assert any(
        finding.title == "Workstation Session User Changed"
        for finding in findings
    )


def test_frequent_unlock_detection():
    events = [
        create_event("workstation_unlock", minutes=index)
        for index in range(5)
    ]

    findings = detect_workstation_activity(
        events,
        unlock_threshold=5,
    )

    assert any(
        finding.title == "Frequent Workstation Unlock Activity"
        for finding in findings
    )


def test_normal_console_logon_is_not_flagged():
    findings = detect_workstation_activity(
        [create_event("console_logon")]
    )

    assert findings == []


def test_irrelevant_event_is_ignored():
    findings = detect_workstation_activity(
        [
            create_event(
                "storage_copy",
                device_type="external_storage",
            )
        ]
    )

    assert findings == []


def test_workstation_single_event_findings_preserve_utc_time():
    offset = timezone(timedelta(hours=3))

    cases = [
        (
            create_event("remote_logon"),
            datetime(2026, 7, 15, 12, 0, tzinfo=offset),
            "Remote Workstation Logon Detected",
            "2026-07-15T09:00:00+00:00",
        ),
        (
            create_event("console_logon"),
            datetime(2026, 7, 15, 6, 0, tzinfo=offset),
            "Console Logon Outside Working Hours",
            "2026-07-15T03:00:00+00:00",
        ),
        (
            create_event(
                "session_switch",
                user="admin",
                previous_user="alex",
            ),
            datetime(2026, 7, 15, 12, 0, tzinfo=offset),
            "Workstation Session User Changed",
            "2026-07-15T09:00:00+00:00",
        ),
    ]

    for event, timestamp, expected_title, expected_time in cases:
        event.timestamp = timestamp

        findings = detect_workstation_activity([event])

        matching = [
            finding
            for finding in findings
            if finding.title == expected_title
        ]

        assert len(matching) == 1
        assert matching[0].first_seen == expected_time
        assert matching[0].last_seen == expected_time


def test_unlock_after_device_connection_preserves_time_range():
    connection = create_event(
        "usb_insert",
        device_type="USB",
        device_name="Unknown USB Device",
        device_id="USB-001",
    )

    connection.timestamp = datetime(
        2026, 7, 15, 12, 0,
        tzinfo=timezone(timedelta(hours=3)),
    )

    unlock = create_event("workstation_unlock")

    unlock.timestamp = datetime(
        2026, 7, 15, 9, 2,
        tzinfo=timezone.utc,
    )

    findings = detect_workstation_activity([
        unlock,
        connection,
    ])

    matching = [
        finding
        for finding in findings
        if finding.title
        == "Workstation Unlocked After Physical Device Connection"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.first_seen == "2026-07-15T09:00:00+00:00"
    assert finding.last_seen == "2026-07-15T09:02:00+00:00"


def test_frequent_unlocks_preserve_per_user_host_time_range():
    start = datetime(
        2026, 7, 15, 9, 0,
        tzinfo=timezone.utc,
    )

    events = [
        create_event("workstation_unlock")
        for _ in range(5)
    ]

    for event, minute in zip(events, (0, 1, 3, 4, 5)):
        event.timestamp = start + timedelta(minutes=minute)

    other_user = create_event(
        "workstation_unlock",
        user="bob",
    )
    other_user.timestamp = start - timedelta(minutes=30)

    other_host = create_event(
        "workstation_unlock",
        hostname="WORKSTATION-02",
    )
    other_host.timestamp = start + timedelta(minutes=30)

    findings = detect_workstation_activity([
        other_host,
        events[4],
        events[2],
        other_user,
        events[0],
        events[3],
        events[1],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Frequent Workstation Unlock Activity"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.first_seen == "2026-07-15T09:00:00+00:00"
    assert finding.last_seen == "2026-07-15T09:05:00+00:00"


def test_workstation_mixed_timezone_awareness_is_safe():
    naive_event = create_event(
        "remote_logon",
        hostname="NAIVE-HOST",
    )

    naive_event.timestamp = datetime(
        2026, 7, 15, 9, 0,
    )

    aware_event = create_event(
        "remote_logon",
        hostname="AWARE-HOST",
    )

    aware_event.timestamp = datetime(
        2026, 7, 15, 12, 0,
        tzinfo=timezone(timedelta(hours=3)),
    )

    findings = detect_workstation_activity([
        aware_event,
        naive_event,
    ])

    assert len(findings) == 2

    by_host = {
        finding.hostname: finding
        for finding in findings
    }

    assert by_host["NAIVE-HOST"].first_seen is None
    assert by_host["NAIVE-HOST"].last_seen is None

    assert (
        by_host["AWARE-HOST"].first_seen
        == "2026-07-15T09:00:00+00:00"
    )
    assert (
        by_host["AWARE-HOST"].last_seen
        == "2026-07-15T09:00:00+00:00"
    )


def test_console_working_hours_use_event_local_clock():
    event = create_event("console_logon")

    event.timestamp = datetime(
        2026, 7, 15, 8, 0,
        tzinfo=timezone(timedelta(hours=3)),
    )

    findings = detect_workstation_activity([event])

    assert findings == []


def test_mixed_timezone_events_do_not_create_false_correlation():
    connection = create_event(
        "usb_insert",
        device_type="USB",
        device_name="Unknown USB Device",
        device_id="USB-MIXED",
    )

    connection.timestamp = datetime(
        2026, 7, 15, 9, 0,
        tzinfo=timezone.utc,
    )

    unlock = create_event("workstation_unlock")

    # Timezone is unknown.
    unlock.timestamp = datetime(
        2026, 7, 15, 9, 2,
    )

    findings = detect_workstation_activity([
        unlock,
        connection,
    ])

    assert not any(
        finding.title
        == "Workstation Unlocked After Physical Device Connection"
        for finding in findings
    )
