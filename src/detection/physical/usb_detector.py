from datetime import timezone
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
    inserted_device_times: dict[str, list[str | None]] = {}

    for event in events:
        if event.device_type.lower() != "usb":
            continue

        if event.event_type != "usb_insert":
            continue

        inserted_device_ids.append(event.device_id)

        event_time = (
            event.timestamp.astimezone(timezone.utc).isoformat()
            if event.timestamp.tzinfo is not None
            else None
        )

        inserted_device_times.setdefault(
            event.device_id, []
        ).append(event_time)

        if event.device_id in blocked_devices:
            findings.append(
                ThreatFinding(
                    title="Blocked USB Device Connected",
                    severity="critical",
                    first_seen=event_time,
                    last_seen=event_time,
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
                    first_seen=event_time,
                    last_seen=event_time,
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
                    first_seen=event_time,
                    last_seen=event_time,
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
                    first_seen=event_time,
                    last_seen=event_time,
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

        device_times = inserted_device_times[device_id]

        known_times = [
            timestamp
            for timestamp in device_times
            if timestamp is not None
        ]

        complete_time_range = len(known_times) == count

        first_seen = (
            min(known_times) if complete_time_range else None
        )
        last_seen = (
            max(known_times) if complete_time_range else None
        )

        findings.append(
            ThreatFinding(
                title="Repeated USB Device Connections",
                severity="medium",
                first_seen=first_seen,
                last_seen=last_seen,
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