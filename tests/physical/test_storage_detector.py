from datetime import datetime, timedelta, timezone

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


def test_storage_findings_preserve_utc_event_time():
    timestamp = datetime(
        2026, 7, 16, 12, 0,
        tzinfo=timezone(timedelta(hours=3)),
    )

    cases = [
        (
            create_storage_event("ST-BLOCKED"),
            {"blocked_devices": {"ST-BLOCKED"}},
            "Blocked External Storage Device Connected",
        ),
        (
            create_storage_event("ST-TRUSTED"),
            {"trusted_devices": {"ST-TRUSTED"}},
            "Trusted External Storage Device Connected",
        ),
        (
            create_storage_event("ST-UNKNOWN"),
            {},
            "Unknown External Storage Device Connected",
        ),
        (
            create_storage_event(
                "ST-NO-SERIAL",
                serial_number=None,
            ),
            {},
            "External Storage Device Without Serial Number",
        ),
        (
            create_storage_event(
                "ST-MOUNT",
                event_type="storage_mount",
            ),
            {},
            "External Storage Device Mounted",
        ),
        (
            create_storage_event(
                "ST-TRANSFER",
                event_type="storage_copy",
                bytes_transferred=250 * 1024 * 1024,
            ),
            {},
            "Large Data Transfer to External Storage",
        ),
        (
            create_storage_event(
                "ST-FILES",
                event_type="storage_copy",
                file_count=1000,
            ),
            {},
            "Large Number of Files Copied to External Storage",
        ),
        (
            create_storage_event(
                "ST-SENSITIVE",
                event_type="storage_access",
                source_path="/home/analyst/documents",
            ),
            {},
            "Sensitive Path Accessed by External Storage",
        ),
    ]

    for event, options, expected_title in cases:
        event.timestamp = timestamp

        findings = detect_storage_activity(
            [event],
            **options,
        )

        matching = [
            finding
            for finding in findings
            if finding.title == expected_title
        ]

        assert len(matching) == 1

        assert (
            matching[0].first_seen
            == "2026-07-16T09:00:00+00:00"
        )
        assert (
            matching[0].last_seen
            == "2026-07-16T09:00:00+00:00"
        )


def test_repeated_storage_connections_preserve_time_range():
    start = datetime(
        2026, 7, 16, 9, 0,
        tzinfo=timezone.utc,
    )

    events = [
        create_storage_event("ST-REPEAT")
        for _ in range(3)
    ]

    for event, minute in zip(events, (0, 2, 5)):
        event.timestamp = start + timedelta(minutes=minute)

    unrelated = create_storage_event("ST-OTHER")
    unrelated.timestamp = start - timedelta(minutes=30)

    copy_event = create_storage_event(
        "ST-REPEAT",
        event_type="storage_copy",
        bytes_transferred=250 * 1024 * 1024,
    )
    copy_event.timestamp = start + timedelta(minutes=30)

    findings = detect_storage_activity([
        copy_event,
        events[2],
        unrelated,
        events[1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Repeated External Storage Connections"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.first_seen == "2026-07-16T09:00:00+00:00"
    assert finding.last_seen == "2026-07-16T09:05:00+00:00"


def test_storage_unknown_timezone_is_not_invented():
    event = create_storage_event("ST-NAIVE")

    event.timestamp = datetime(
        2026, 7, 16, 9, 0
    )

    findings = detect_storage_activity([event])

    matching = [
        finding
        for finding in findings
        if finding.title == "Unknown External Storage Device Connected"
    ]

    assert len(matching) == 1
    assert matching[0].first_seen is None
    assert matching[0].last_seen is None

    # Mixed timezone awareness in aggregated connections
    # must not produce a misleading time range.

    events = [
        create_storage_event("ST-MIXED")
        for _ in range(3)
    ]

    events[0].timestamp = datetime(
        2026, 7, 16, 9, 0,
        tzinfo=timezone.utc,
    )

    events[1].timestamp = datetime(
        2026, 7, 16, 9, 2
    )

    events[2].timestamp = datetime(
        2026, 7, 16, 9, 5,
        tzinfo=timezone.utc,
    )

    findings = detect_storage_activity(events)

    repeated = [
        finding
        for finding in findings
        if finding.title == "Repeated External Storage Connections"
    ]

    assert len(repeated) == 1
    assert repeated[0].first_seen is None
    assert repeated[0].last_seen is None
