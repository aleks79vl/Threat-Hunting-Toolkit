
from collections import defaultdict

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding
from src.utils.event_time import normalize_event_time


FAILED_LOGIN_THRESHOLD = 3


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


def detect_successful_login_after_failures(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    events_by_ip = defaultdict(list)

    # Group only relevant SSH authentication events.
    for event in events:
        if (
            event.service == "ssh"
            and event.action == "authentication"
            and event.source_ip
            and event.status in ("failed", "success")
        ):
            events_by_ip[event.source_ip].append(event)

    findings = []

    for source_ip, source_events in events_by_ip.items():
        normalized_times = [
            normalize_event_time(event.timestamp_utc)
            for event in source_events
        ]

        has_reliable_chronology = all(
            timestamp is not None
            for timestamp in normalized_times
        )

        if has_reliable_chronology:
            ordered_events = sorted(
                zip(source_events, normalized_times),
                key=lambda item: (
                    _utc_sort_key(item[1]),
                    # At identical timestamps, a failure
                    # cannot be proven to precede success.
                    0 if item[0].status == "success" else 1,
                ),
            )
        else:
            # Preserve legacy detection behavior when
            # the chronological order cannot be verified.
            ordered_events = [
                (event, None)
                for event in source_events
            ]

        failed_count = 0
        first_failed_time = None


        for event, event_time in ordered_events:

            if event.status == "failed":
                failed_count += 1

                if (
                    has_reliable_chronology
                    and first_failed_time is None
                ):
                    first_failed_time = event_time

            elif (
                event.status == "success"
                and failed_count >= FAILED_LOGIN_THRESHOLD
            ):
                findings.append(
                    ThreatFinding(
                        title="Successful Login After Failures Detected",
                        severity="critical",
                        description=(
                            f"Successful SSH login for user "
                            f"{event.user} from {source_ip} "
                            f"occurred after {failed_count} "
                            f"failed authentication attempts."
                        ),
                        source="Linux Log Detection",
                        ip=source_ip,
                        hostname=event.hostname,
                        port=22,
                        recommendation=(
                            "Investigate whether the account "
                            "was compromised after repeated "
                            "failed authentication attempts."
                        ),
                        first_seen=(
                            first_failed_time
                            if has_reliable_chronology
                            else None
                        ),
                        last_seen=(
                            event_time
                            if has_reliable_chronology
                            else None
                        ),
                    )
                )

                # Preserve one finding per source IP.
                break

    return findings
