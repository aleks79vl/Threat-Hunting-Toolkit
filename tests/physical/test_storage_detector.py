from datetime import datetime

from src.detection.physical.storage_detector import (
    detect_storage_activity,
)
from src.models.physical_event import PhysicalEvent


def create_storage_event(
    device_id: str,
    *,
    event_type: str = "storage_connect",
    device_name: str = "External SSD",
    trusted: bool = False,
    serial_number: str | None = "SERIAL-001",
    bytes_transferred: int | None = None,
    file_count: int | None = None,
    source_path: str | None = None,
    destination_path: str | None = None,
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=datetime.now(),
        event_type=event_type,
        device_type="external_storage",
        device_name=device_name,
        device_id=device_id,
        hostname="WORKSTATION-01",
        user="alex",
        trusted=trusted,
        serial_number=serial_number,
        bytes_transferred=bytes_transferred,
        file_count=file_count,
        source_path=source_path,
        destination_path=destination_path,
    )


def test_unknown_storage_device_detection():
    event = create_storage_event("STORAGE-UNKNOWN-001")

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "Unknown External Storage Device Connected" in titles


def test_trusted_storage_device_detection():
    event = create_storage_event("STORAGE-TRUSTED-001")

    findings = detect_storage_activity(
        [event],
        trusted_devices={"STORAGE-TRUSTED-001"},
    )

    titles = [finding.title for finding in findings]

    assert "Trusted External Storage Device Connected" in titles
    assert "Unknown External Storage Device Connected" not in titles


def test_blocked_storage_device_detection():
    event = create_storage_event("STORAGE-BLOCKED-001")

    findings = detect_storage_activity(
        [event],
        blocked_devices={"STORAGE-BLOCKED-001"},
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Blocked External Storage Device Connected"
    )
    assert findings[0].severity == "critical"


def test_storage_device_without_serial_number():
    event = create_storage_event(
        "STORAGE-NO-SERIAL",
        serial_number=None,
    )

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "External Storage Device Without Serial Number" in titles


def test_external_storage_mount_detection():
    event = create_storage_event(
        "STORAGE-MOUNT-001",
        event_type="storage_mount",
    )

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "External Storage Device Mounted" in titles


def test_large_data_transfer_detection():
    event = create_storage_event(
        "STORAGE-COPY-001",
        event_type="storage_copy",
        bytes_transferred=250 * 1024 * 1024,
    )

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "Large Data Transfer to External Storage" in titles


def test_large_file_count_detection():
    event = create_storage_event(
        "STORAGE-FILES-001",
        event_type="storage_copy",
        file_count=1000,
    )

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "Large Number of Files Copied to External Storage" in titles


def test_sensitive_path_access_detection():
    event = create_storage_event(
        "STORAGE-SENSITIVE-001",
        event_type="storage_copy",
        source_path="C:\\Users\\alex\\Documents\\Confidential",
        destination_path="E:\\Backup",
    )

    findings = detect_storage_activity([event])

    titles = [finding.title for finding in findings]

    assert "Sensitive Path Accessed by External Storage" in titles


def test_repeated_storage_connections_detection():
    events = [
        create_storage_event("STORAGE-REPEAT-001"),
        create_storage_event("STORAGE-REPEAT-001"),
        create_storage_event("STORAGE-REPEAT-001"),
    ]

    findings = detect_storage_activity(events)

    titles = [finding.title for finding in findings]

    assert "Repeated External Storage Connections" in titles


def test_non_storage_event_is_ignored():
    event = PhysicalEvent(
        timestamp=datetime.now(),
        event_type="hid_connect",
        device_type="HID",
        device_name="Keyboard",
        device_id="HID-001",
    )

    assert detect_storage_activity([event]) == []