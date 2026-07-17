from datetime import datetime

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