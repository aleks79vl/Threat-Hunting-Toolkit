from datetime import datetime

from src.detection.physical.usb_detector import detect_usb_devices
from src.models.physical_event import PhysicalEvent


def create_usb_event(
    device_id: str,
    *,
    device_name: str = "Kingston DataTraveler",
    trusted: bool = False,
    action: str | None = None,
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=datetime.now(),
        event_type="usb_insert",
        device_type="USB",
        device_name=device_name,
        device_id=device_id,
        hostname="WORKSTATION-01",
        user="alex",
        trusted=trusted,
        action=action,
    )


def test_unknown_usb_device_detection():
    event = create_usb_event("USB-UNKNOWN-001")

    findings = detect_usb_devices([event])

    assert len(findings) == 1
    assert findings[0].title == "Unknown USB Device Connected"
    assert findings[0].severity == "high"


def test_trusted_usb_device_detection():
    event = create_usb_event("USB-TRUSTED-001")

    findings = detect_usb_devices(
        [event],
        trusted_devices={"USB-TRUSTED-001"},
    )

    assert len(findings) == 1
    assert findings[0].title == "Trusted USB Device Connected"
    assert findings[0].severity == "low"


def test_event_trusted_flag_is_supported():
    event = create_usb_event(
        "USB-TRUSTED-FLAG",
        trusted=True,
    )

    findings = detect_usb_devices([event])

    assert len(findings) == 1
    assert findings[0].title == "Trusted USB Device Connected"


def test_blocked_usb_device_detection():
    event = create_usb_event("USB-BLOCKED-001")

    findings = detect_usb_devices(
        [event],
        blocked_devices={"USB-BLOCKED-001"},
    )

    assert len(findings) == 1
    assert findings[0].title == "Blocked USB Device Connected"
    assert findings[0].severity == "critical"


def test_usb_storage_mount_detection():
    event = create_usb_event(
        "USB-STORAGE-001",
        action="storage_mount",
    )

    findings = detect_usb_devices([event])

    titles = [finding.title for finding in findings]

    assert "Unknown USB Device Connected" in titles
    assert "USB Storage Device Mounted" in titles


def test_repeated_usb_connections_detection():
    events = [
        create_usb_event("USB-REPEAT-001"),
        create_usb_event("USB-REPEAT-001"),
        create_usb_event("USB-REPEAT-001"),
    ]

    findings = detect_usb_devices(
        events,
        repeated_connection_threshold=3,
    )

    titles = [finding.title for finding in findings]

    assert "Repeated USB Device Connections" in titles


def test_non_usb_events_are_ignored():
    event = PhysicalEvent(
        timestamp=datetime.now(),
        event_type="bluetooth_connect",
        device_type="Bluetooth",
        device_name="Bluetooth Keyboard",
        device_id="BT-001",
    )

    findings = detect_usb_devices([event])

    assert findings == []


def test_usb_removal_is_not_flagged_as_connection():
    event = PhysicalEvent(
        timestamp=datetime.now(),
        event_type="usb_remove",
        device_type="USB",
        device_name="Kingston DataTraveler",
        device_id="USB-001",
    )

    findings = detect_usb_devices([event])

    assert findings == []