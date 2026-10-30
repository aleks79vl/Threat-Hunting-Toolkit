from collections import Counter, defaultdict
from datetime import datetime, time, timezone

from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


WORKSTATION_EVENT_TYPES = {
    "workstation_lock",
    "workstation_unlock",
    "console_logon",
    "remote_logon",
    "session_switch",
}


def _is_aware(timestamp: datetime | None) -> bool:
    return (
        timestamp is not None
        and timestamp.tzinfo is not None
        and timestamp.utcoffset() is not None
    )


def _workstation_time_range(
    events: list[PhysicalEvent],
) -> tuple[str | None, str | None]:
    if not events:
        return None, None

    timestamps = []

    for event in events:
        timestamp = event.timestamp

        if not _is_aware(timestamp):
            return None, None

        timestamps.append(
            timestamp.astimezone(timezone.utc)
        )

    return (
        min(timestamps).isoformat(),
        max(timestamps).isoformat(),
    )


def _event_sort_key(
    event: PhysicalEvent,
) -> tuple[int, datetime]:
    timestamp = event.timestamp

    if timestamp is None:
        return (2, datetime.max)

    if _is_aware(timestamp):
        return (
            0,
            timestamp.astimezone(timezone.utc),
        )

    return (1, timestamp)


def _timestamps_comparable(
    first: datetime | None,
    second: datetime | None,
) -> bool:
    if first is None or second is None:
        return False

    return _is_aware(first) == _is_aware(second)


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
    unlock_events_by_identity = defaultdict(list)

    sorted_events = sorted(events, key=_event_sort_key)

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

        first_seen, last_seen = _workstation_time_range([event])

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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        if (
            event.event_type == "console_logon"
            and event.timestamp is not None
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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        if event.event_type == "workstation_unlock":
            identity = (hostname, user)

            unlock_counts[identity] += 1
            unlock_events_by_identity[identity].append(event)

            previous_events = sorted_events[:index]

            recent_device_event = next(
                (
                    previous
                    for previous in reversed(previous_events)
                    if (
                        previous.event_type in device_connection_events
                        and previous.hostname == event.hostname
                        and _timestamps_comparable(
                            event.timestamp,
                            previous.timestamp,
                        )
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
                correlation_first, correlation_last = (
                    _workstation_time_range(
                        [recent_device_event, event]
                    )
                )

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
                        first_seen=correlation_first,
                        last_seen=correlation_last,
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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    for (hostname, user), count in unlock_counts.items():
        if count < unlock_threshold:
            continue

        first_seen, last_seen = _workstation_time_range(
            unlock_events_by_identity[(hostname, user)]
        )

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
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    return findings