from dataclasses import dataclass, field

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


@dataclass
class DevicePolicy:
    """
    Enterprise physical-device policy.

    Empty allowlists mean that no explicit allowlist restriction is applied
    for the corresponding attribute.
    """

    allowed_device_ids: set[str] = field(default_factory=set)
    blocked_device_ids: set[str] = field(default_factory=set)

    allowed_device_types: set[str] = field(default_factory=set)
    blocked_device_types: set[str] = field(default_factory=set)

    allowed_users: set[str] = field(default_factory=set)
    allowed_hosts: set[str] = field(default_factory=set)

    require_serial_number: bool = False
    require_encrypted_storage: bool = False
    require_read_only_storage: bool = False
    require_signed_driver: bool = False

    bluetooth_enabled: bool = True
    external_storage_enabled: bool = True
    hid_enabled: bool = True


STORAGE_DEVICE_TYPES = {
    "storage",
    "external_storage",
    "usb_storage",
    "external_drive",
}

HID_DEVICE_TYPES = {
    "hid",
    "keyboard",
    "mouse",
}

DEVICE_CONNECTION_EVENTS = {
    "usb_insert",
    "hid_connect",
    "keyboard_connect",
    "mouse_connect",
    "bluetooth_connect",
    "storage_connect",
    "usb_storage_connect",
    "external_drive_connect",
    "device_install",
    "driver_install",
}


def _finding(
    *,
    title: str,
    severity: str,
    description: str,
    event: PhysicalEvent,
    recommendation: str,
) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity=severity,
        description=description,
        source="Device Policy Detector",
        hostname=event.hostname or "",
        recommendation=recommendation,
    )


def detect_device_policy_violations(
    events: list[PhysicalEvent],
    policy: DevicePolicy,
) -> list[ThreatFinding]:
    """
    Detect violations of enterprise physical-device policies.

    Rules:
    - explicitly blocked device ID;
    - blocked or unauthorized device type;
    - unauthorized user or host;
    - missing serial number;
    - Bluetooth disabled by policy;
    - HID disabled by policy;
    - external storage disabled by policy;
    - unencrypted external storage;
    - writable external storage where read-only is required;
    - unsigned device driver.
    """

    findings: list[ThreatFinding] = []

    normalized_allowed_types = {
        value.lower()
        for value in policy.allowed_device_types
    }
    normalized_blocked_types = {
        value.lower()
        for value in policy.blocked_device_types
    }

    for event in events:
        device_type = event.device_type.lower()

        if event.event_type not in DEVICE_CONNECTION_EVENTS:
            continue

        if event.device_id in policy.blocked_device_ids:
            findings.append(
                _finding(
                    title="Blocked Device Policy Violation",
                    severity="critical",
                    description=(
                        f"Device '{event.device_name}' with ID "
                        f"'{event.device_id}' is explicitly blocked."
                    ),
                    event=event,
                    recommendation=(
                        "Disconnect the device immediately and investigate "
                        "the associated user and endpoint."
                    ),
                )
            )

        if (
            policy.allowed_device_ids
            and event.device_id not in policy.allowed_device_ids
        ):
            findings.append(
                _finding(
                    title="Device Not Present in Allowlist",
                    severity="high",
                    description=(
                        f"Device '{event.device_name}' with ID "
                        f"'{event.device_id}' is not present in the "
                        "approved-device allowlist."
                    ),
                    event=event,
                    recommendation=(
                        "Verify device ownership and approve or block the "
                        "device according to corporate policy."
                    ),
                )
            )

        if device_type in normalized_blocked_types:
            findings.append(
                _finding(
                    title="Blocked Device Type Connected",
                    severity="critical",
                    description=(
                        f"Device type '{event.device_type}' is prohibited "
                        "by policy."
                    ),
                    event=event,
                    recommendation=(
                        "Disconnect the device and review endpoint "
                        "device-control enforcement."
                    ),
                )
            )

        if (
            normalized_allowed_types
            and device_type not in normalized_allowed_types
        ):
            findings.append(
                _finding(
                    title="Unauthorized Device Type Connected",
                    severity="high",
                    description=(
                        f"Device type '{event.device_type}' is not included "
                        "in the permitted device types."
                    ),
                    event=event,
                    recommendation=(
                        "Confirm business justification and update the policy "
                        "only after formal approval."
                    ),
                )
            )

        if (
            policy.allowed_users
            and (
                not event.user
                or event.user not in policy.allowed_users
            )
        ):
            findings.append(
                _finding(
                    title="Unauthorized User Connected Physical Device",
                    severity="high",
                    description=(
                        f"User '{event.user or 'unknown'}' connected "
                        f"device '{event.device_name}' without policy "
                        "authorization."
                    ),
                    event=event,
                    recommendation=(
                        "Verify the user's authorization and inspect "
                        "subsequent device activity."
                    ),
                )
            )

        if (
            policy.allowed_hosts
            and (
                not event.hostname
                or event.hostname not in policy.allowed_hosts
            )
        ):
            findings.append(
                _finding(
                    title="Device Connected to Unauthorized Host",
                    severity="high",
                    description=(
                        f"Device '{event.device_name}' was connected to "
                        f"host '{event.hostname or 'unknown'}', which is "
                        "not approved by policy."
                    ),
                    event=event,
                    recommendation=(
                        "Review host authorization and endpoint device "
                        "control configuration."
                    ),
                )
            )

        if policy.require_serial_number and not event.serial_number:
            findings.append(
                _finding(
                    title="Device Missing Required Serial Number",
                    severity="medium",
                    description=(
                        f"Device '{event.device_name}' does not provide "
                        "the serial number required by policy."
                    ),
                    event=event,
                    recommendation=(
                        "Block unidentified devices or collect additional "
                        "hardware identifiers."
                    ),
                )
            )

        if device_type == "bluetooth" and not policy.bluetooth_enabled:
            findings.append(
                _finding(
                    title="Bluetooth Device Prohibited by Policy",
                    severity="high",
                    description=(
                        f"Bluetooth device '{event.device_name}' was "
                        "connected while Bluetooth use is disabled."
                    ),
                    event=event,
                    recommendation=(
                        "Disable the Bluetooth connection and review "
                        "endpoint wireless-device policy."
                    ),
                )
            )

        if device_type in HID_DEVICE_TYPES and not policy.hid_enabled:
            findings.append(
                _finding(
                    title="HID Device Prohibited by Policy",
                    severity="critical",
                    description=(
                        f"HID device '{event.device_name}' was connected "
                        "while external HID devices are disabled."
                    ),
                    event=event,
                    recommendation=(
                        "Disconnect the HID device and investigate possible "
                        "BadUSB or input-injection activity."
                    ),
                )
            )

        if device_type in STORAGE_DEVICE_TYPES:
            if not policy.external_storage_enabled:
                findings.append(
                    _finding(
                        title="External Storage Prohibited by Policy",
                        severity="critical",
                        description=(
                            f"Storage device '{event.device_name}' was "
                            "connected while external storage is disabled."
                        ),
                        event=event,
                        recommendation=(
                            "Disconnect the storage device and investigate "
                            "file access or transfer activity."
                        ),
                    )
                )

            if (
                policy.require_encrypted_storage
                and event.encrypted is not True
            ):
                findings.append(
                    _finding(
                        title="Unencrypted External Storage Device",
                        severity="high",
                        description=(
                            f"Storage device '{event.device_name}' does not "
                            "meet the encryption requirement."
                        ),
                        event=event,
                        recommendation=(
                            "Block write access and require an approved "
                            "encrypted corporate storage device."
                        ),
                    )
                )

            if (
                policy.require_read_only_storage
                and event.read_only is not True
            ):
                findings.append(
                    _finding(
                        title="Writable External Storage Policy Violation",
                        severity="high",
                        description=(
                            f"Storage device '{event.device_name}' is "
                            "writable although read-only access is required."
                        ),
                        event=event,
                        recommendation=(
                            "Enforce read-only access and review recent "
                            "file-write activity."
                        ),
                    )
                )

        if (
            event.event_type == "driver_install"
            and policy.require_signed_driver
            and event.driver_signed is not True
        ):
            findings.append(
                _finding(
                    title="Unsigned Device Driver Installation",
                    severity="critical",
                    description=(
                        f"An unsigned driver was installed for device "
                        f"'{event.device_name}'."
                    ),
                    event=event,
                    recommendation=(
                        "Block the driver, isolate the endpoint if necessary "
                        "and verify driver provenance."
                    ),
                )
            )

    return findings