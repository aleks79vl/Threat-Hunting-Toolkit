
from collections import defaultdict

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding
from src.utils.event_time import normalize_event_time


REPEATED_SERVICE_MANIPULATION_THRESHOLD = 3

MONITORED_SERVICE_ACTIONS = {
    "service_stop",
    "service_restart",
}


def _utc_sort_key(timestamp: str) -> tuple[str, int]:
    """
    Compare normalized UTC timestamps with
    nanosecond precision.
    """
    value = timestamp.removesuffix("+00:00")
    seconds, separator, fraction = value.partition(".")

    nanoseconds = (
        int(fraction.ljust(9, "0"))
        if separator
        else 0
    )

    return seconds, nanoseconds


def _group_time_range(
    events: list[LinuxEvent],
) -> tuple[str | None, str | None]:
    """
    Calculate the time range for one detection group.

    Unknown or invalid time in any contributing
    event makes the group's time range unreliable.
    """
    if not events:
        return None, None

    normalized_times = [
        normalize_event_time(event.timestamp_utc)
        for event in events
    ]

    if any(
        timestamp is None
        for timestamp in normalized_times
    ):
        return None, None

    valid_times = [
        timestamp
        for timestamp in normalized_times
        if timestamp is not None
    ]

    return (
        min(valid_times, key=_utc_sort_key),
        max(valid_times, key=_utc_sort_key),
    )


def detect_linux_service_manipulation(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    lifecycle_groups = defaultdict(list)
    process_groups = defaultdict(list)

    # Collect only monitored service actions.
    for event in events:
        if event.action not in MONITORED_SERVICE_ACTIONS:
            continue

        lifecycle_key = (
            event.hostname,
            event.message,
        )

        process_key = (
            event.hostname,
            event.process,
        )

        lifecycle_groups[lifecycle_key].append(event)
        process_groups[process_key].append(event)

    # One lifecycle finding per (hostname, message).
    for lifecycle_key, group in lifecycle_groups.items():
        hostname, message = lifecycle_key

        first_seen, last_seen = _group_time_range(group)

        findings.append(
            ThreatFinding(
                title="Linux Service Manipulation Detected",
                severity="medium",
                description=(
                    f"Linux service lifecycle activity detected "
                    f"on host {hostname}: {message}"
                ),
                source="Linux Log Detection",
                hostname=hostname,
                recommendation=(
                    "Review the service lifecycle event and verify "
                    "whether the stop or restart action was authorized."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    # One repeated finding per (hostname, process)
    # when the existing threshold is reached.
    for process_key, group in process_groups.items():
        count = len(group)

        if count < REPEATED_SERVICE_MANIPULATION_THRESHOLD:
            continue

        hostname, process = process_key

        first_seen, last_seen = _group_time_range(group)

        findings.append(
            ThreatFinding(
                title="Repeated Linux Service Manipulation Detected",
                severity="high",
                description=(
                    f"Repeated Linux service lifecycle activity was "
                    f"detected on host {hostname}. Process {process} "
                    f"generated {count} monitored service actions."
                ),
                source="Linux Log Detection",
                hostname=hostname,
                recommendation=(
                    "Investigate repeated service stop or restart activity "
                    "and validate whether automated or administrative "
                    "service manipulation is expected."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    return findings
