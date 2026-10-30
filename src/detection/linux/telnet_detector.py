
from collections import defaultdict

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding
from src.utils.event_time import normalize_event_time


TELNET_REPEATED_ATTEMPTS_THRESHOLD = 5


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
    timestamps: list[str | None],
) -> tuple[str | None, str | None]:
    """
    Calculate the earliest and latest UTC timestamps.

    If any contributing event has an unknown or
    invalid timestamp, the range is unreliable.
    """
    if not timestamps:
        return None, None

    normalized_times = [
        normalize_event_time(timestamp)
        for timestamp in timestamps
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


def detect_telnet_activity(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    events_by_source = defaultdict(list)

    # Group Telnet events by source IP.
    for event in events:
        if event.service != "telnet":
            continue

        events_by_source[event.source_ip].append(event)

    time_ranges = {}

    # Preserve one activity finding per source IP.
    for source_ip, source_events in events_by_source.items():
        first_event = source_events[0]

        first_seen, last_seen = _group_time_range(
            [
                event.timestamp_utc
                for event in source_events
            ]
        )

        time_ranges[source_ip] = (
            first_seen,
            last_seen,
        )

        findings.append(
            ThreatFinding(
                title="Telnet Activity Detected",
                severity="medium",
                description=(
                    f"Telnet activity detected from "
                    f"{source_ip} on host {first_event.hostname}."
                ),
                source="Linux Log Detection",
                ip=source_ip,
                hostname=first_event.hostname,
                port=23,
                recommendation=(
                    "Review Telnet usage. Replace Telnet with SSH "
                    "where possible because Telnet is insecure."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    # Preserve repeated-attempt detection threshold.
    for source_ip, source_events in events_by_source.items():
        if not source_ip:
            continue

        count = len(source_events)

        if count >= TELNET_REPEATED_ATTEMPTS_THRESHOLD:
            first_seen, last_seen = time_ranges[source_ip]

            findings.append(
                ThreatFinding(
                    title="Repeated Telnet Login Attempts Detected",
                    severity="high",
                    description=(
                        f"Source IP {source_ip} generated {count} "
                        f"Telnet connection or login attempts."
                    ),
                    source="Linux Log Detection",
                    ip=source_ip,
                    port=23,
                    recommendation=(
                        "Investigate repeated Telnet activity and block "
                        "unauthorized source IPs."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    return findings
