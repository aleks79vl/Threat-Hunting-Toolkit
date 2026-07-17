from collections import Counter

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


def detect_usb_devices(
    events: list[PhysicalEvent],
    trusted_devices: set[str] | None = None,
    blocked_devices: set[str] | None = None,
    repeated_connection_threshold: int = 3,
) -> list[ThreatFinding]:
    """
    Detect suspicious USB activity.

    Rules:
    - blocked USB device connection;
    - unknown USB device connection;
    - trusted USB device connection;
    - USB storage device connection;
    - repeated USB connections.
    """

    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    findings: list[ThreatFinding] = []
    inserted_device_ids: list[str] = []

    for event in events:
        if event.device_type.lower() != "usb":
            continue

        if event.event_type != "usb_insert":
            continue

        inserted_device_ids.append(event.device_id)

        if event.device_id in blocked_devices:
            findings.append(
                ThreatFinding(
                    title="Blocked USB Device Connected",
                    severity="critical",
                    description=(
                        f"Blocked USB device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="USB Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Disconnect the device immediately and investigate "
                        "the associated user and workstation."
                    ),
                )
            )
            continue

        if event.device_id in trusted_devices or event.trusted:
            findings.append(
                ThreatFinding(
                    title="Trusted USB Device Connected",
                    severity="low",
                    description=(
                        f"Trusted USB device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="USB Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "No immediate action is required. Retain the event "
                        "for audit and correlation."
                    ),
                )
            )
        else:
            findings.append(
                ThreatFinding(
                    title="Unknown USB Device Connected",
                    severity="high",
                    description=(
                        f"Unknown USB device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="USB Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Verify device ownership, business justification "
                        "and authorization status."
                    ),
                )
            )

        if event.action == "storage_mount":
            findings.append(
                ThreatFinding(
                    title="USB Storage Device Mounted",
                    severity="medium",
                    description=(
                        f"USB storage device '{event.device_name}' "
                        f"was mounted on host '{event.hostname or 'unknown'}'."
                    ),
                    source="USB Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Review file access and copy activity associated "
                        "with the mounted USB storage device."
                    ),
                )
            )

    connection_counts = Counter(inserted_device_ids)

    for device_id, count in connection_counts.items():
        if count < repeated_connection_threshold:
            continue

        findings.append(
            ThreatFinding(
                title="Repeated USB Device Connections",
                severity="medium",
                description=(
                    f"USB device '{device_id}' was connected "
                    f"{count} times during the analyzed event set."
                ),
                source="USB Detector",
                recommendation=(
                    "Review whether repeated device reconnections indicate "
                    "policy bypass, unstable hardware or suspicious activity."
                ),
            )
        )

    return findings