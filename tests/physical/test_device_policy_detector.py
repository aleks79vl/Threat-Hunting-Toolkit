from datetime import datetime

from src.detection.physical.device_policy_detector import (
    DevicePolicy,
    detect_device_policy_violations,
)
from src.models.physical_event import PhysicalEvent


def create_event(
    *,
    event_type: str = "usb_insert",
    device_type: str = "USB",
    device_id: str = "DEVICE-001",
    device_name: str = "Generic Device",
    user: str | None = "alex",
    hostname: str | None = "WORKSTATION-01",
    serial_number: str | None = "SERIAL-001",
    encrypted: bool | None = None,
    read_only: bool | None = None,
    driver_signed: bool | None = None,
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=datetime.now(),
        event_type=event_type,
        device_type=device_type,
        device_name=device_name,
        device_id=device_id,
        user=user,
        hostname=hostname,
        serial_number=serial_number,
        encrypted=encrypted,
        read_only=read_only,
        driver_signed=driver_signed,
    )


def titles(findings):
    return {
        finding.title
        for finding in findings
    }


def test_blocked_device_id():
    policy = DevicePolicy(
        blocked_device_ids={"DEVICE-BLOCKED"},
    )
    event = create_event(device_id="DEVICE-BLOCKED")

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Blocked Device Policy Violation" in titles(findings)


def test_device_not_in_allowlist():
    policy = DevicePolicy(
        allowed_device_ids={"DEVICE-APPROVED"},
    )
    event = create_event(device_id="DEVICE-UNKNOWN")

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Device Not Present in Allowlist" in titles(findings)


def test_blocked_device_type():
    policy = DevicePolicy(
        blocked_device_types={"bluetooth"},
    )
    event = create_event(
        event_type="bluetooth_connect",
        device_type="Bluetooth",
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Blocked Device Type Connected" in titles(findings)


def test_unauthorized_user():
    policy = DevicePolicy(
        allowed_users={"security-admin"},
    )
    event = create_event(user="guest")

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert (
        "Unauthorized User Connected Physical Device"
        in titles(findings)
    )


def test_unauthorized_host():
    policy = DevicePolicy(
        allowed_hosts={"WORKSTATION-SECURE"},
    )
    event = create_event(hostname="WORKSTATION-01")

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Device Connected to Unauthorized Host" in titles(findings)


def test_missing_serial_number():
    policy = DevicePolicy(
        require_serial_number=True,
    )
    event = create_event(serial_number=None)

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Device Missing Required Serial Number" in titles(findings)


def test_bluetooth_disabled():
    policy = DevicePolicy(
        bluetooth_enabled=False,
    )
    event = create_event(
        event_type="bluetooth_connect",
        device_type="Bluetooth",
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Bluetooth Device Prohibited by Policy" in titles(findings)


def test_hid_disabled():
    policy = DevicePolicy(
        hid_enabled=False,
    )
    event = create_event(
        event_type="hid_connect",
        device_type="HID",
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "HID Device Prohibited by Policy" in titles(findings)


def test_external_storage_disabled():
    policy = DevicePolicy(
        external_storage_enabled=False,
    )
    event = create_event(
        event_type="storage_connect",
        device_type="external_storage",
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "External Storage Prohibited by Policy" in titles(findings)


def test_unencrypted_storage():
    policy = DevicePolicy(
        require_encrypted_storage=True,
    )
    event = create_event(
        event_type="storage_connect",
        device_type="external_storage",
        encrypted=False,
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Unencrypted External Storage Device" in titles(findings)


def test_writable_storage_when_read_only_required():
    policy = DevicePolicy(
        require_read_only_storage=True,
    )
    event = create_event(
        event_type="storage_connect",
        device_type="external_storage",
        read_only=False,
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert (
        "Writable External Storage Policy Violation"
        in titles(findings)
    )


def test_unsigned_driver_installation():
    policy = DevicePolicy(
        require_signed_driver=True,
    )
    event = create_event(
        event_type="driver_install",
        device_type="USB",
        driver_signed=False,
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert "Unsigned Device Driver Installation" in titles(findings)


def test_compliant_device_has_no_findings():
    policy = DevicePolicy(
        allowed_device_ids={"DEVICE-001"},
        allowed_device_types={"usb"},
        allowed_users={"alex"},
        allowed_hosts={"WORKSTATION-01"},
        require_serial_number=True,
    )

    event = create_event()

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert findings == []


def test_irrelevant_event_is_ignored():
    policy = DevicePolicy(
        allowed_device_ids={"DEVICE-001"},
    )

    event = create_event(
        event_type="storage_copy",
        device_type="external_storage",
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert findings == []