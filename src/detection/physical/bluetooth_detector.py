from collections import Counter

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


def detect_bluetooth_activity(
    events: list[PhysicalEvent],
    trusted_devices=None,
    blocked_devices=None,
):
    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    findings = []
    connected = []

    for event in events:

        if event.device_type.lower() != "bluetooth":
            continue

        connected.append(event.device_id)

        if event.device_id in blocked_devices:

            findings.append(
                ThreatFinding(
                    title="Blocked Bluetooth Device Connected",
                    severity="critical",
                   description=f"{event.device_name}",
                   source="Bluetooth Detector",
                   hostname=event.hostname or "",
                   recommendation="Disconnect immediately."
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
                   recommendation="Audit only."
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
                   recommendation="Verify authorization."
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
                   recommendation="Collect additional device metadata."
                )
            )

        name = event.device_name.lower()

        if any(marker in name for marker in SUSPICIOUS_DEVICE_MARKERS):

            findings.append(
                ThreatFinding(
                    title="Potential Rogue Bluetooth Device",
                    severity="high",
                   description=event.device_name,
                   source="Bluetooth Detector",
                   hostname=event.hostname or "",
                   recommendation="Investigate device usage."
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
                   recommendation="Review transferred files."
                )
            )

    counts = Counter(connected)

    for device, count in counts.items():

        if count >= 3:

            findings.append(
                ThreatFinding(
                    title="Repeated Bluetooth Connections",
                    severity="medium",
                   description=f"{device} connected {count} times",
                   source="Bluetooth Detector",
                   recommendation="Review device activity."
                )
            )

    return findings