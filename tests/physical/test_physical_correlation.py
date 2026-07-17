from datetime import datetime, timedelta

from src.detection.physical.physical_correlation import (
    correlate_physical_events,
)
from src.models.physical_event import PhysicalEvent


BASE_TIME = datetime(2026, 7, 15, 12, 0, 0)


def create_event(
    event_type: str,
    *,
    minutes: int = 0,
    device_type: str = "HID",
    device_name: str = "Generic Device",
    device_id: str = "DEVICE-001",
    hostname: str = "WORKSTATION-01",
    user: str = "alex",
    command: str | None = None,
    action: str | None = None,
    bytes_transferred: int | None = None,
    file_count: int | None = None,
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        event_type=event_type,
        device_type=device_type,
        device_name=device_name,
        device_id=device_id,
        hostname=hostname,
        user=user,
        command=command,
        action=action,
        bytes_transferred=bytes_transferred,
        file_count=file_count,
    )


def test_empty_event_list_returns_no_findings():
    assert correlate_physical_events([]) == []


def test_device_connection_followed_by_policy_violation():
    events = [
        create_event(
            "usb_insert",
            device_type="USB",
            device_name="Unknown USB",
            device_id="USB-001",
        ),
        create_event(
            "device_policy_violation",
            minutes=1,
            device_type="USB",
            device_name="Unknown USB",
            device_id="USB-001",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Physical Device Connection Followed by Policy Violation"
        in titles
    )


def test_policy_violation_followed_by_workstation_access():
    events = [
        create_event(
            "device_policy_violation",
            device_type="USB",
        ),
        create_event(
            "workstation_unlock",
            minutes=1,
            device_type="workstation",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Device Policy Violation Followed by Workstation Access"
        in titles
    )


def test_workstation_access_followed_by_hid_command():
    events = [
        create_event(
            "workstation_unlock",
            device_type="workstation",
        ),
        create_event(
            "hid_input",
            minutes=1,
            command="powershell -enc AAAA",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Workstation Access Followed by Suspicious HID Command"
        in titles
    )


def test_hid_command_followed_by_large_storage_transfer():
    events = [
        create_event(
            "hid_input",
            command="cmd.exe /c whoami",
        ),
        create_event(
            "storage_copy",
            minutes=2,
            device_type="external_storage",
            bytes_transferred=250 * 1024 * 1024,
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Suspicious HID Command Followed by "
        "Large Storage Transfer"
        in titles
    )


def test_storage_transfer_followed_by_bluetooth_transfer():
    events = [
        create_event(
            "storage_copy",
            device_type="external_storage",
            bytes_transferred=250 * 1024 * 1024,
        ),
        create_event(
            "bluetooth_file_transfer",
            minutes=2,
            device_type="bluetooth",
            action="file_transfer",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Large Storage Transfer Followed by Bluetooth Transfer"
        in titles
    )


def test_complete_physical_attack_chain():
    events = [
        create_event(
            "hid_connect",
            device_name="USB Rubber Ducky",
            device_id="HID-001",
        ),
        create_event(
            "device_policy_violation",
            minutes=1,
            device_name="USB Rubber Ducky",
            device_id="HID-001",
        ),
        create_event(
            "workstation_unlock",
            minutes=2,
            device_type="workstation",
            device_name="Corporate Workstation",
            device_id="WS-001",
        ),
        create_event(
            "hid_input",
            minutes=3,
            command="powershell -enc AAAA",
        ),
        create_event(
            "storage_copy",
            minutes=5,
            device_type="external_storage",
            bytes_transferred=500 * 1024 * 1024,
            file_count=1000,
        ),
        create_event(
            "bluetooth_file_transfer",
            minutes=7,
            device_type="bluetooth",
            action="file_transfer",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert "Multi-Stage Physical Attack Chain Detected" in titles


def test_events_outside_window_are_not_correlated():
    events = [
        create_event("usb_insert"),
        create_event(
            "device_policy_violation",
            minutes=20,
        ),
    ]

    findings = correlate_physical_events(
        events,
        correlation_window_minutes=10,
    )

    titles = [finding.title for finding in findings]

    assert (
        "Physical Device Connection Followed by Policy Violation"
        not in titles
    )


def test_events_on_different_hosts_are_not_correlated():
    events = [
        create_event(
            "usb_insert",
            hostname="WORKSTATION-01",
        ),
        create_event(
            "device_policy_violation",
            minutes=1,
            hostname="WORKSTATION-02",
        ),
    ]

    findings = correlate_physical_events(events)

    titles = [finding.title for finding in findings]

    assert (
        "Physical Device Connection Followed by Policy Violation"
        not in titles
    )