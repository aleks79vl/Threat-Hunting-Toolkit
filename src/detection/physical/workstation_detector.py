from collections import Counter
from datetime import time

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


WORKSTATION_EVENT_TYPES = {
    "workstation_lock",
    "workstation_unlock",
    "console_logon",
    "remote_logon",
    "session_switch",
}


def _is_outside_working_hours(
    event: PhysicalEvent,
    workday_start: time,
    workday_end: time,
) -> bool:
    event_time = event.timestamp.time()

    return not (workday_start <= event_time <= workday_end)


def detect_workstation_activity(
    events: list[PhysicalEvent],
    unlock_threshold: int = 5,
    workday_start: time = time(7, 0),
    workday_end: time = time(20, 0),
) -> list[ThreatFinding]:
    """
    Detect suspicious workstation and session activity.

    Rules:
    - remote logon;
    - console logon outside working hours;
    - frequent workstation unlocks;
    - session switch to a different user;
    - unlock after physical-device connection.
    """

    findings: list[ThreatFinding] = []
    unlock_counts: Counter[tuple[str, str]] = Counter()

    sorted_events = sorted(events, key=lambda event: event.timestamp)

    device_connection_events = {
        "usb_insert",
        "hid_connect",
        "keyboard_connect",
        "mouse_connect",
        "bluetooth_connect",
        "storage_connect",
        "usb_storage_connect",
        "external_drive_connect",
    }

    for index, event in enumerate(sorted_events):
        if event.event_type not in WORKSTATION_EVENT_TYPES:
            continue

        hostname = event.hostname or "unknown"
        user = event.user or "unknown"

        if event.event_type == "remote_logon":
            findings.append(
                ThreatFinding(
                    title="Remote Workstation Logon Detected",
                    severity="medium",
                    description=(
                        f"Remote logon by user '{user}' was detected "
                        f"on host '{hostname}'."
                    ),
                    source="Workstation Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Verify that the remote session was authorized "
                        "and review the source endpoint."
                    ),
                )
            )

        if (
            event.event_type == "console_logon"
            and _is_outside_working_hours(
                event,
                workday_start,
                workday_end,
            )
        ):
            findings.append(
                ThreatFinding(
                    title="Console Logon Outside Working Hours",
                    severity="high",
                    description=(
                        f"Console logon by user '{user}' occurred outside "
                        f"working hours on host '{hostname}'."
                    ),
                    source="Workstation Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Verify physical access authorization and review "
                        "related workstation and badge activity."
                    ),
                )
            )

        if event.event_type == "workstation_unlock":
            unlock_counts[(hostname, user)] += 1

            previous_events = sorted_events[:index]

            recent_device_event = next(
                (
                    previous
                    for previous in reversed(previous_events)
                    if (
                        previous.event_type in device_connection_events
                        and previous.hostname == event.hostname
                        and 0
                        <= (
                            event.timestamp - previous.timestamp
                        ).total_seconds()
                        <= 300
                    )
                ),
                None,
            )

            if recent_device_event is not None:
                findings.append(
                    ThreatFinding(
                        title=(
                            "Workstation Unlocked After "
                            "Physical Device Connection"
                        ),
                        severity="high",
                        description=(
                            f"Host '{hostname}' was unlocked shortly after "
                            f"device '{recent_device_event.device_name}' "
                            "was connected."
                        ),
                        source="Workstation Detector",
                        hostname=event.hostname or "",
                        recommendation=(
                            "Review whether the connected device was used "
                            "to influence or bypass workstation access."
                        ),
                    )
                )

        if (
            event.event_type == "session_switch"
            and event.previous_user
            and event.user
            and event.previous_user != event.user
        ):
            findings.append(
                ThreatFinding(
                    title="Workstation Session User Changed",
                    severity="medium",
                    description=(
                        f"Workstation session changed from "
                        f"'{event.previous_user}' to '{event.user}' "
                        f"on host '{hostname}'."
                    ),
                    source="Workstation Detector",
                    hostname=event.hostname or "",
                    recommendation=(
                        "Verify whether the user switch was authorized "
                        "and review authentication activity."
                    ),
                )
            )

    for (hostname, user), count in unlock_counts.items():
        if count < unlock_threshold:
            continue

        findings.append(
            ThreatFinding(
                title="Frequent Workstation Unlock Activity",
                severity="medium",
                description=(
                    f"User '{user}' unlocked host '{hostname}' "
                    f"{count} times during the analyzed event set."
                ),
                source="Workstation Detector",
                hostname=hostname if hostname != "unknown" else "",
                recommendation=(
                    "Review session activity for shared credentials, "
                    "automation or suspicious physical access."
                ),
            )
        )

    return findings