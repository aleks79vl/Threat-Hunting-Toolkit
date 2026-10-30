from collections import Counter, defaultdict

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding
from src.utils.event_time import normalize_event_time


SSH_BRUTE_FORCE_THRESHOLD = 5


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
    Return earliest and latest UTC timestamps.

    If any contributing event has an unknown
    or invalid time, return (None, None).
    """
    if not timestamps:
        return None, None

    normalized_times = [
        normalize_event_time(timestamp)
        for timestamp in timestamps
    ]

    if any(value is None for value in normalized_times):
        return None, None

    valid_times = [
        value
        for value in normalized_times
        if value is not None
    ]

    return (
        min(valid_times, key=_utc_sort_key),
        max(valid_times, key=_utc_sort_key),
    )


def detect_ssh_bruteforce(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    failed_attempts = Counter()
    hostnames = {}
    failed_attempt_times = defaultdict(list)

    for event in events:
        if (
            event.service == "ssh"
            and event.action == "authentication"
            and event.status == "failed"
            and event.source_ip
        ):
            failed_attempts[event.source_ip] += 1
            hostnames[event.source_ip] = event.hostname

            failed_attempt_times[event.source_ip].append(
                event.timestamp_utc
            )

    findings = []

    for source_ip, count in failed_attempts.items():
        if count >= SSH_BRUTE_FORCE_THRESHOLD:
            first_seen, last_seen = _group_time_range(
                failed_attempt_times[source_ip]
            )

            findings.append(
                ThreatFinding(
                    title="SSH Brute Force Detected",
                    severity="high",
                    description=(
                        f"Source IP {source_ip} generated {count} "
                        f"failed SSH authentication attempts."
                    ),
                    source="Linux Log Detection",
                    ip=source_ip,
                    hostname=hostnames.get(source_ip, ""),
                    port=22,
                    recommendation=(
                        "Block or investigate the source IP and review "
                        "SSH authentication logs for brute-force activity."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    return findings
