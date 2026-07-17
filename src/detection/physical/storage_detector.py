from collections import Counter

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


SENSITIVE_PATH_MARKERS = (
    "/etc/",
    "/home/",
    "/root/",
    "/var/lib/",
    "c:\\users\\",
    "c:\\windows\\system32\\config\\",
    "documents",
    "desktop",
    "downloads",
    "password",
    "credentials",
    "secrets",
    "finance",
    "confidential",
)

STORAGE_DEVICE_TYPES = {
    "storage",
    "external_storage",
    "usb_storage",
    "external_drive",
}


def detect_storage_activity(
    events: list[PhysicalEvent],
    trusted_devices: set[str] | None = None,
    blocked_devices: set[str] | None = None,
    large_transfer_threshold: int = 100 * 1024 * 1024,
    large_file_count_threshold: int = 500,
    repeated_connection_threshold: int = 3,
) -> list[ThreatFinding]:
    """
    Detect suspicious external storage activity.

    Rules:
    - blocked storage device connection;
    - unknown storage device connection;
    - trusted storage device connection;
    - storage device without serial number;
    - external storage mount;
    - large data transfer;
    - large file-count transfer;
    - sensitive path access;
    - repeated device connections.
    """

    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    findings: list[ThreatFinding] = []
    connected_device_ids: list[str] = []

    connection_event_types = {
        "storage_connect",
        "usb_storage_connect",
        "external_drive_connect",
    }

    accepted_event_types = connection_event_types | {
        "storage_mount",
        "storage_copy",
        "file_copy",
        "storage_access",
    }

    for event in events:
        if event.device_type.lower() not in STORAGE_DEVICE_TYPES:
            continue

        if event.event_type not in accepted_event_types:
            continue

        if event.event_type in connection_event_types:
            connected_device_ids.append(event.device_id)

        if event.device_id in blocked_devices:
            findings.append(
                ThreatFinding(
                    title="Blocked External Storage Device Connected",
                    severity="critical",
                    description=(
                        f"Blocked storage device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="Storage Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Disconnect the device immediately and investigate "
                        "the associated user and workstation."
                    ),
                )
            )
            continue

        if event.event_type in connection_event_types:
            if event.device_id in trusted_devices or event.trusted:
                findings.append(
                    ThreatFinding(
                        title="Trusted External Storage Device Connected",
                        severity="low",
                        description=(
                            f"Trusted storage device '{event.device_name}' "
                            f"with ID '{event.device_id}' was connected."
                        ),
                        source="Storage Detector",
                        hostname=event.hostname or "",
                        recommendation=(
                            "Retain the event for audit and monitor subsequent "
                            "file-transfer activity."
                        ),
                    )
                )
            else:
                findings.append(
                    ThreatFinding(
                        title="Unknown External Storage Device Connected",
                        severity="high",
                        description=(
                            f"Unknown storage device '{event.device_name}' "
                            f"with ID '{event.device_id}' was connected."
                        ),
                        source="Storage Detector",
                        hostname=event.hostname or "",
                        recommendation=(
                            "Verify ownership, authorization and business "
                            "justification for the external storage device."
                        ),
                    )
                )

            if not event.serial_number:
                findings.append(
                    ThreatFinding(
                        title="External Storage Device Without Serial Number",
                        severity="medium",
                        description=(
                            f"Storage device '{event.device_name}' was connected "
                            "without an available serial number."
                        ),
                        source="Storage Detector",
                        hostname=event.hostname or "",
                        recommendation=(
                            "Review device metadata and apply stricter device "
                            "control policy when identification is incomplete."
                        ),
                    )
                )

        if event.event_type == "storage_mount" or event.action == "storage_mount":
            findings.append(
                ThreatFinding(
                    title="External Storage Device Mounted",
                    severity="medium",
                    description=(
                        f"External storage device '{event.device_name}' "
                        f"was mounted on host '{event.hostname or 'unknown'}'."
                    ),
                    source="Storage Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Monitor file access and copy activity associated "
                        "with the mounted storage device."
                    ),
                )
            )

        if (
            event.bytes_transferred is not None
            and event.bytes_transferred >= large_transfer_threshold
        ):
            findings.append(
                ThreatFinding(
                    title="Large Data Transfer to External Storage",
                    severity="high",
                    description=(
                        f"{event.bytes_transferred} bytes were transferred "
                        f"using storage device '{event.device_name}'."
                    ),
                    source="Storage Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Review transferred files, destination path and user "
                        "authorization for possible data exfiltration."
                    ),
                )
            )

        if (
            event.file_count is not None
            and event.file_count >= large_file_count_threshold
        ):
            findings.append(
                ThreatFinding(
                    title="Large Number of Files Copied to External Storage",
                    severity="high",
                    description=(
                        f"{event.file_count} files were copied using storage "
                        f"device '{event.device_name}'."
                    ),
                    source="Storage Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Investigate the copied file set and determine whether "
                        "the activity was authorized."
                    ),
                )
            )

        paths = (
            event.source_path or "",
            event.destination_path or "",
        )

        for path in paths:
            normalized_path = path.lower()

            if any(
                marker in normalized_path
                for marker in SENSITIVE_PATH_MARKERS
            ):
                findings.append(
                    ThreatFinding(
                        title="Sensitive Path Accessed by External Storage",
                        severity="critical",
                        description=(
                            f"External storage activity involved sensitive "
                            f"path '{path}'."
                        ),
                        source="Storage Detector",
                        hostname=event.hostname or "",
                        recommendation=(
                            "Review the accessed files, isolate the endpoint "
                            "if necessary and investigate possible exfiltration."
                        ),
                    )
                )
                break

    connection_counts = Counter(connected_device_ids)

    for device_id, count in connection_counts.items():
        if count < repeated_connection_threshold:
            continue

        findings.append(
            ThreatFinding(
                title="Repeated External Storage Connections",
                severity="medium",
                description=(
                    f"Storage device '{device_id}' was connected "
                    f"{count} times during the analyzed event set."
                ),
                source="Storage Detector",
                recommendation=(
                    "Review whether repeated reconnections indicate policy "
                    "bypass, device testing or suspicious activity."
                ),
            )
        )

    return findings