from datetime import datetime, timedelta, timezone

from src.models.physical_event import PhysicalEvent
from src.detection.physical.bluetooth_detector import (
    detect_bluetooth_activity,
)


def bt_event(
    device_id,
    name="Bluetooth Keyboard",
    action=None,
):

    return PhysicalEvent(
        timestamp=datetime.now(),
        event_type="bluetooth_connect",
        device_type="bluetooth",
        device_name=name,
        device_id=device_id,
        hostname="HOST",
        serial_number="BT123",
        action=action,
    )


def test_unknown():

    findings = detect_bluetooth_activity(
        [bt_event("BT1")]
    )

    assert any(
        f.title == "Unknown Bluetooth Device Connected"
        for f in findings
    )


def test_blocked():

    findings = detect_bluetooth_activity(
        [bt_event("BT2")],
        blocked_devices={"BT2"},
    )

    assert findings[0].severity == "critical"


def test_trusted():

    findings = detect_bluetooth_activity(
        [bt_event("BT3")],
        trusted_devices={"BT3"},
    )

    assert any(
        f.title == "Trusted Bluetooth Device Connected"
        for f in findings
    )


def test_file_transfer():

    findings = detect_bluetooth_activity(
        [bt_event("BT4", action="file_transfer")]
    )

    assert any(
        f.title == "Bluetooth File Transfer"
        for f in findings
    )


def test_repeat():

    events = [
        bt_event("BT5"),
        bt_event("BT5"),
        bt_event("BT5"),
    ]

    findings = detect_bluetooth_activity(events)

    assert any(
        f.title == "Repeated Bluetooth Connections"
        for f in findings
    )


def test_bluetooth_event_preserves_utc_time():
    event = bt_event(
        "BT-UTC",
        action="file_transfer",
    )

    event.timestamp = datetime(
        2026, 7, 16, 12, 0,
        tzinfo=timezone(timedelta(hours=3)),
    )
    event.serial_number = None

    findings = detect_bluetooth_activity([event])

    expected_titles = {
        "Unknown Bluetooth Device Connected",
        "Bluetooth Device Without Identifier",
        "Potential Rogue Bluetooth Device",
        "Bluetooth File Transfer",
    }

    assert {f.title for f in findings} == expected_titles

    for finding in findings:
        assert finding.first_seen == "2026-07-16T09:00:00+00:00"
        assert finding.last_seen == "2026-07-16T09:00:00+00:00"


def test_bluetooth_blocked_and_trusted_preserve_time():
    expected_time = "2026-07-16T09:00:00+00:00"

    cases = [
        (
            {"blocked_devices": {"BT-001"}},
            "Blocked Bluetooth Device Connected",
        ),
        (
            {"trusted_devices": {"BT-001"}},
            "Trusted Bluetooth Device Connected",
        ),
    ]

    for options, expected_title in cases:
        event = bt_event(
            "BT-001",
            name="Bluetooth Speaker",
        )

        event.timestamp = datetime(
            2026, 7, 16, 9, 0,
            tzinfo=timezone.utc,
        )

        findings = detect_bluetooth_activity(
            [event],
            **options,
        )

        matching = [
            finding
            for finding in findings
            if finding.title == expected_title
        ]

        assert len(matching) == 1
        assert matching[0].first_seen == expected_time
        assert matching[0].last_seen == expected_time


def test_repeated_bluetooth_connections_preserve_time_range():
    start = datetime(
        2026, 7, 16, 9, 0,
        tzinfo=timezone.utc,
    )

    events = [
        bt_event("BT-REPEAT", name="Bluetooth Speaker")
        for _ in range(3)
    ]

    for event, minute in zip(events, (0, 2, 5)):
        event.timestamp = start + timedelta(minutes=minute)

    other_event = bt_event(
        "BT-OTHER",
        name="Bluetooth Speaker",
    )
    other_event.timestamp = start - timedelta(minutes=30)

    findings = detect_bluetooth_activity([
        events[2],
        other_event,
        events[1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Repeated Bluetooth Connections"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.first_seen == "2026-07-16T09:00:00+00:00"
    assert finding.last_seen == "2026-07-16T09:05:00+00:00"
