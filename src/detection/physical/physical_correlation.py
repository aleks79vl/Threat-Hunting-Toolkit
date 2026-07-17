from datetime import timedelta

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


DEFAULT_CORRELATION_WINDOW_MINUTES = 10

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

POLICY_VIOLATION_EVENTS = {
    "device_policy_violation",
    "blocked_device",
    "unauthorized_device",
    "unauthorized_device_type",
    "unencrypted_storage",
    "unsigned_driver",
}

WORKSTATION_ACCESS_EVENTS = {
    "workstation_unlock",
    "console_logon",
    "remote_logon",
    "session_switch",
}

HID_INPUT_EVENTS = {
    "hid_input",
}

STORAGE_ACTIVITY_EVENTS = {
    "storage_mount",
    "storage_copy",
    "file_copy",
    "storage_access",
}

BLUETOOTH_TRANSFER_EVENTS = {
    "bluetooth_file_transfer",
}

SUSPICIOUS_COMMAND_MARKERS = (
    "powershell",
    "cmd.exe",
    "bash",
    "curl ",
    "wget ",
    "certutil",
    "invoke-webrequest",
    "python -c",
    "python3 -c",
)


def _same_scope(
    first: PhysicalEvent,
    second: PhysicalEvent,
) -> bool:
    if first.hostname and second.hostname:
        if first.hostname != second.hostname:
            return False

    if first.user and second.user:
        if first.user != second.user:
            return False

    return True


def _within_window(
    first: PhysicalEvent,
    second: PhysicalEvent,
    window: timedelta,
) -> bool:
    delta = second.timestamp - first.timestamp
    return timedelta(0) <= delta <= window


def _is_suspicious_command(event: PhysicalEvent) -> bool:
    command = (event.command or "").lower()

    return any(
        marker in command
        for marker in SUSPICIOUS_COMMAND_MARKERS
    )


def _is_large_storage_activity(event: PhysicalEvent) -> bool:
    large_transfer = (
        event.bytes_transferred is not None
        and event.bytes_transferred >= 100 * 1024 * 1024
    )

    many_files = (
        event.file_count is not None
        and event.file_count >= 500
    )

    return large_transfer or many_files


def correlate_physical_events(
    events: list[PhysicalEvent],
    correlation_window_minutes: int = (
        DEFAULT_CORRELATION_WINDOW_MINUTES
    ),
) -> list[ThreatFinding]:
    """
    Correlate physical security events into attack chains.

    Rules:
    - Device connection followed by policy violation.
    - Policy violation followed by workstation access.
    - Workstation access followed by suspicious HID command.
    - Suspicious HID command followed by large storage transfer.
    - Large storage transfer followed by Bluetooth transfer.
    - Full multi-stage physical attack chain.
    """

    if not events:
        return []

    sorted_events = sorted(
        events,
        key=lambda event: event.timestamp,
    )

    window = timedelta(
        minutes=correlation_window_minutes,
    )

    findings: list[ThreatFinding] = []

    connections = [
        event
        for event in sorted_events
        if event.event_type in DEVICE_CONNECTION_EVENTS
    ]

    policy_violations = [
        event
        for event in sorted_events
        if event.event_type in POLICY_VIOLATION_EVENTS
    ]

    workstation_events = [
        event
        for event in sorted_events
        if event.event_type in WORKSTATION_ACCESS_EVENTS
    ]

    suspicious_commands = [
        event
        for event in sorted_events
        if (
            event.event_type in HID_INPUT_EVENTS
            and _is_suspicious_command(event)
        )
    ]

    large_storage_events = [
        event
        for event in sorted_events
        if (
            event.event_type in STORAGE_ACTIVITY_EVENTS
            and _is_large_storage_activity(event)
        )
    ]

    bluetooth_transfers = [
        event
        for event in sorted_events
        if (
            event.event_type in BLUETOOTH_TRANSFER_EVENTS
            or event.action == "file_transfer"
        )
    ]

    for connection in connections:
        for violation in policy_violations:
            if not _same_scope(connection, violation):
                continue

            if not _within_window(connection, violation, window):
                continue

            findings.append(
                ThreatFinding(
                    title=(
                        "Physical Device Connection Followed by "
                        "Policy Violation"
                    ),
                    severity="high",
                    description=(
                        f"Device '{connection.device_name}' was connected "
                        f"before policy violation "
                        f"'{violation.event_type}' on host "
                        f"'{connection.hostname or 'unknown'}'."
                    ),
                    source="Physical Correlation Engine",
                    hostname=connection.hostname or "",
                    recommendation=(
                        "Disconnect the device and review the applicable "
                        "device-control policy."
                    ),
                )
            )
            break

    for violation in policy_violations:
        for workstation_event in workstation_events:
            if not _same_scope(violation, workstation_event):
                continue

            if not _within_window(
                violation,
                workstation_event,
                window,
            ):
                continue

            findings.append(
                ThreatFinding(
                    title=(
                        "Device Policy Violation Followed by "
                        "Workstation Access"
                    ),
                    severity="critical",
                    description=(
                        f"Policy violation '{violation.event_type}' was "
                        f"followed by workstation event "
                        f"'{workstation_event.event_type}'."
                    ),
                    source="Physical Correlation Engine",
                    hostname=violation.hostname or "",
                    recommendation=(
                        "Investigate whether the unauthorized device "
                        "was used to gain or influence workstation access."
                    ),
                )
            )
            break

    for workstation_event in workstation_events:
        for command_event in suspicious_commands:
            if not _same_scope(
                workstation_event,
                command_event,
            ):
                continue

            if not _within_window(
                workstation_event,
                command_event,
                window,
            ):
                continue

            findings.append(
                ThreatFinding(
                    title=(
                        "Workstation Access Followed by "
                        "Suspicious HID Command"
                    ),
                    severity="critical",
                    description=(
                        f"Workstation event "
                        f"'{workstation_event.event_type}' was followed "
                        "by suspicious HID command activity."
                    ),
                    source="Physical Correlation Engine",
                    hostname=workstation_event.hostname or "",
                    recommendation=(
                        "Isolate the endpoint and investigate the "
                        "associated device, user and command execution."
                    ),
                )
            )
            break

    for command_event in suspicious_commands:
        for storage_event in large_storage_events:
            if not _same_scope(
                command_event,
                storage_event,
            ):
                continue

            if not _within_window(
                command_event,
                storage_event,
                window,
            ):
                continue

            findings.append(
                ThreatFinding(
                    title=(
                        "Suspicious HID Command Followed by "
                        "Large Storage Transfer"
                    ),
                    severity="critical",
                    description=(
                        "A suspicious HID-entered command was followed "
                        "by large external storage activity."
                    ),
                    source="Physical Correlation Engine",
                    hostname=command_event.hostname or "",
                    recommendation=(
                        "Investigate possible automated execution and "
                        "data exfiltration through external storage."
                    ),
                )
            )
            break

    for storage_event in large_storage_events:
        for bluetooth_event in bluetooth_transfers:
            if not _same_scope(
                storage_event,
                bluetooth_event,
            ):
                continue

            if not _within_window(
                storage_event,
                bluetooth_event,
                window,
            ):
                continue

            findings.append(
                ThreatFinding(
                    title=(
                        "Large Storage Transfer Followed by "
                        "Bluetooth Transfer"
                    ),
                    severity="critical",
                    description=(
                        "Large external storage activity was followed "
                        "by a Bluetooth file transfer."
                    ),
                    source="Physical Correlation Engine",
                    hostname=storage_event.hostname or "",
                    recommendation=(
                        "Investigate possible multi-channel data "
                        "exfiltration and preserve endpoint evidence."
                    ),
                )
            )
            break

    for connection in connections:
        violation = next(
            (
                event
                for event in policy_violations
                if _same_scope(connection, event)
                and _within_window(connection, event, window)
            ),
            None,
        )

        if violation is None:
            continue

        workstation_event = next(
            (
                event
                for event in workstation_events
                if _same_scope(violation, event)
                and _within_window(violation, event, window)
            ),
            None,
        )

        if workstation_event is None:
            continue

        command_event = next(
            (
                event
                for event in suspicious_commands
                if _same_scope(workstation_event, event)
                and _within_window(
                    workstation_event,
                    event,
                    window,
                )
            ),
            None,
        )

        if command_event is None:
            continue

        storage_event = next(
            (
                event
                for event in large_storage_events
                if _same_scope(command_event, event)
                and _within_window(
                    command_event,
                    event,
                    window,
                )
            ),
            None,
        )

        if storage_event is None:
            continue

        bluetooth_event = next(
            (
                event
                for event in bluetooth_transfers
                if _same_scope(storage_event, event)
                and _within_window(
                    storage_event,
                    event,
                    window,
                )
            ),
            None,
        )

        if bluetooth_event is None:
            continue

        findings.append(
            ThreatFinding(
                title="Multi-Stage Physical Attack Chain Detected",
                severity="critical",
                description=(
                    "A physical device connection was followed by a "
                    "device-policy violation, workstation access, "
                    "suspicious HID command execution, large external "
                    "storage activity and Bluetooth transfer."
                ),
                source="Physical Correlation Engine",
                hostname=connection.hostname or "",
                recommendation=(
                    "Immediately isolate the endpoint, disconnect all "
                    "related devices, preserve evidence and investigate "
                    "the complete physical attack timeline."
                ),
            )
        )
        break

    return findings