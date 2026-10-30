from collections import defaultdict

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding
from src.utils.event_time import normalize_event_time


SUSPICIOUS_SUDO_PATTERNS = {
    "chmod 777",
    "useradd",
    "usermod",
    "visudo",
    "/etc/sudoers",
    "curl ",
    "wget ",
    "nc ",
    "netcat ",
    "bash",
    "/bin/sh",
    "python ",
    "python3 ",
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
    timestamps: list[str | None],
) -> tuple[str | None, str | None]:
    """
    Return the earliest and latest UTC timestamps.

    Unknown or invalid time in any contributing
    event makes the entire range unreliable.
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


def detect_sudo_abuse(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    grouped_events = defaultdict(list)

    for event in events:
        if (
            event.service != "sudo"
            or event.action != "command"
        ):
            continue

        message_lower = event.message.lower()

        matched_patterns = {
            pattern
            for pattern in SUSPICIOUS_SUDO_PATTERNS
            if pattern in message_lower
        }

        if not matched_patterns:
            continue

        detection_key = (
            event.hostname,
            event.user,
            event.message,
        )

        grouped_events[detection_key].append(event)

    findings = []

    for detection_key, group in grouped_events.items():
        hostname, user, message = detection_key

        matched_patterns = {
            pattern
            for pattern in SUSPICIOUS_SUDO_PATTERNS
            if pattern in message.lower()
        }

        first_seen, last_seen = _group_time_range(
            [
                event.timestamp_utc
                for event in group
            ]
        )

        findings.append(
            ThreatFinding(
                title="Sudo Abuse Detected",
                severity="high",
                description=(
                    f"Suspicious sudo command activity detected "
                    f"for user {user} on host "
                    f"{hostname}. Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}."
                ),
                source="Linux Log Detection",
                hostname=hostname,
                recommendation=(
                    "Review the sudo command, validate whether the "
                    "privileged activity was authorized, and investigate "
                    "possible privilege abuse."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    return findings
