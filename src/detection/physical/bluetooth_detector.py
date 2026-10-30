from collections import Counter, defaultdict
from datetime import timezone

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_DEVICE_MARKERS = (
    "keyboard",
    "ble keyboard",
    "bluetooth keyboard",
    "android",
    "iphone",
    "phone",
    "mobile",
    "raspberry",
    "esp32",
)


def _event_time_range(
    events: list[PhysicalEvent],
) -> tuple[str | None, str | None]:

    if not events:
        return None, None

    timestamps = []

    for event in events:
        timestamp = event.timestamp

        if (
            timestamp is None
            or timestamp.tzinfo is None
            or timestamp.utcoffset() is None
        ):
            return None, None

        timestamps.append(
            timestamp.astimezone(timezone.utc)
        )

    return (
        min(timestamps).isoformat(),
        max(timestamps).isoformat(),
    )


def detect_bluetooth_activity(
    events: list[PhysicalEvent],
    trusted_devices=None,
    blocked_devices=None,
):
    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    findings = []
    connected = []
    events_by_device = defaultdict(list)

    for event in events:

        if event.device_type.lower() != "bluetooth":
            continue

        connected.append(event.device_id)
        events_by_device[event.device_id].append(event)

        first_seen, last_seen = _event_time_range([event])

        if event.device_id in blocked_devices:

            findings.append(
                ThreatFinding(
                    title="Blocked Bluetooth Device Connected",
                    severity="critical",
                    description=f"{event.device_name}",
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Disconnect immediately.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

            continue

        if event.device_id in trusted_devices:

            findings.append(
                ThreatFinding(
                    title="Trusted Bluetooth Device Connected",
                    severity="low",
                    description=f"{event.device_name}",
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Audit only.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        else:

            findings.append(
                ThreatFinding(
                    title="Unknown Bluetooth Device Connected",
                    severity="high",
                    description=f"{event.device_name}",
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Verify authorization.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        if not event.serial_number:

            findings.append(
                ThreatFinding(
                    title="Bluetooth Device Without Identifier",
                    severity="medium",
                    description=event.device_name,
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Collect additional device metadata.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        name = event.device_name.lower()

        if any(
            marker in name
            for marker in SUSPICIOUS_DEVICE_MARKERS
        ):

            findings.append(
                ThreatFinding(
                    title="Potential Rogue Bluetooth Device",
                    severity="high",
                    description=event.device_name,
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Investigate device usage.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        if event.action == "file_transfer":

            findings.append(
                ThreatFinding(
                    title="Bluetooth File Transfer",
                    severity="high",
                    description=event.device_name,
                    source="Bluetooth Detector",
                    hostname=event.hostname or "",
                    recommendation="Review transferred files.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    counts = Counter(connected)

    for device, count in counts.items():

        if count >= 3:

            first_seen, last_seen = _event_time_range(
                events_by_device[device]
            )

            findings.append(
                ThreatFinding(
                    title="Repeated Bluetooth Connections",
                    severity="medium",
                    description=f"{device} connected {count} times",
                    source="Bluetooth Detector",
                    recommendation="Review device activity.",
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    return findings