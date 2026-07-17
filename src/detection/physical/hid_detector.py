from collections import Counter

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_COMMAND_MARKERS = (
    "powershell",
    "cmd.exe",
    "bash",
    "sh ",
    "terminal",
    "curl ",
    "wget ",
    "certutil",
    "invoke-webrequest",
    "iex ",
    "python -c",
    "python3 -c",
)

SUSPICIOUS_DEVICE_MARKERS = (
    "rubber ducky",
    "badusb",
    "ducky",
    "keystroke injector",
    "programmable keyboard",
)


def detect_hid_attacks(
    events: list[PhysicalEvent],
    trusted_devices: set[str] | None = None,
    blocked_devices: set[str] | None = None,
    input_rate_threshold: float = 15.0,
    repeated_connection_threshold: int = 3,
) -> list[ThreatFinding]:
    """Detect suspicious HID activity."""

    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    findings: list[ThreatFinding] = []
    connected_device_ids: list[str] = []

    connection_event_types = {
        "hid_connect",
        "keyboard_connect",
        "mouse_connect",
    }

    accepted_event_types = connection_event_types | {"hid_input"}
    accepted_device_types = {"hid", "keyboard", "mouse"}

    for event in events:
        if event.device_type.lower() not in accepted_device_types:
            continue

        if event.event_type not in accepted_event_types:
            continue

        if event.event_type in connection_event_types:
            connected_device_ids.append(event.device_id)

        device_name_lower = event.device_name.lower()
        command_lower = (event.command or "").lower()

        if event.device_id in blocked_devices:
            findings.append(
                ThreatFinding(
                    title="Blocked HID Device Connected",
                    severity="critical",
                    description=(
                        f"Blocked HID device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="HID Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Disconnect the device immediately and investigate "
                        "the user and workstation."
                    ),
                )
            )
            continue

        if any(
            marker in device_name_lower
            for marker in SUSPICIOUS_DEVICE_MARKERS
        ):
            findings.append(
                ThreatFinding(
                    title="Potential BadUSB or Rubber Ducky Device",
                    severity="critical",
                    description=(
                        f"Suspicious HID device '{event.device_name}' "
                        f"was detected on host "
                        f"'{event.hostname or 'unknown'}'."
                    ),
                    source="HID Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Isolate the workstation, disconnect the device and "
                        "review command execution and process activity."
                    ),
                )
            )

        if (
            event.event_type in connection_event_types
            and event.device_id not in trusted_devices
            and not event.trusted
        ):
            findings.append(
                ThreatFinding(
                    title="Unknown HID Device Connected",
                    severity="high",
                    description=(
                        f"Unknown HID device '{event.device_name}' "
                        f"with ID '{event.device_id}' was connected."
                    ),
                    source="HID Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Verify whether the device is authorized and review "
                        "subsequent user and process activity."
                    ),
                )
            )

        if (
            event.input_rate is not None
            and event.input_rate >= input_rate_threshold
        ):
            findings.append(
                ThreatFinding(
                    title="Abnormally Fast HID Input Detected",
                    severity="high",
                    description=(
                        f"HID device '{event.device_name}' generated input "
                        f"at {event.input_rate:.2f} events per second."
                    ),
                    source="HID Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Review the input sequence for automated keystroke "
                        "injection or scripted execution."
                    ),
                )
            )

        if command_lower and any(
            marker in command_lower
            for marker in SUSPICIOUS_COMMAND_MARKERS
        ):
            findings.append(
                ThreatFinding(
                    title="Suspicious Command Entered by HID Device",
                    severity="critical",
                    description=(
                        f"HID device '{event.device_name}' entered a "
                        f"suspicious command: '{event.command}'."
                    ),
                    source="HID Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Investigate command execution, isolate the endpoint "
                        "and review related PowerShell or shell activity."
                    ),
                )
            )

    connection_counts = Counter(connected_device_ids)

    for device_id, count in connection_counts.items():
        if count < repeated_connection_threshold:
            continue

        findings.append(
            ThreatFinding(
                title="Repeated HID Device Connections",
                severity="medium",
                description=(
                    f"HID device '{device_id}' was connected "
                    f"{count} times during the analyzed event set."
                ),
                source="HID Detector",
                recommendation=(
                    "Review whether repeated reconnections indicate device "
                    "testing, policy bypass or suspicious activity."
                ),
            )
        )

    return findings