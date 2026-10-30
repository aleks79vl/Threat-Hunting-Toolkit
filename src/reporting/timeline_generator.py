import re
from datetime import datetime, timezone

from src.models.threat_finding import ThreatFinding


ISO_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def _normalize_event_time(
    value: str | None,
) -> str | None:
    """
    Normalize an ISO 8601 timestamp to UTC.

    Preserve source fractional precision up to
    nine digits (nanoseconds).

    Return None for invalid timestamps or
    timestamps without timezone information.
    """

    if not isinstance(value, str) or not value:
        return None

    match = ISO_TIMESTAMP_PATTERN.fullmatch(value)

    if match is None:
        return None

    try:
        event_time = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if event_time.tzinfo is None:
            return None

        # Convert the whole-second portion to UTC.
        # Python datetime supports microseconds only,
        # so the fractional part is handled separately.
        utc_second = (
            event_time
            .replace(microsecond=0)
            .astimezone(timezone.utc)
        )

        normalized_time = utc_second.isoformat(
            timespec="seconds"
        )

        # Preserve the exact source fractional digits,
        # including nanoseconds and trailing zeros.
        fraction = match.group("fraction")

        if fraction is not None:
            normalized_time = normalized_time.replace(
                "+00:00",
                f".{fraction}+00:00",
            )

        return normalized_time

    except (ValueError, OverflowError):
        return None


def generate_timeline(
    findings: list[ThreatFinding],
) -> list[dict]:
    """
    Generate a chronological timeline from findings.

    Preserve UTC nanosecond timestamps.
    Place events with unknown timestamps last.
    """

    timeline = []

    for finding in findings:
        timeline.append(
            {
                "time": _normalize_event_time(
                    finding.first_seen
                ),
                "event": finding.title,
                "severity": finding.severity,
                "ip": finding.ip,
                "port": finding.port,
                "risk_score": finding.risk_score,
                "source": finding.source,
            }
        )

    # All valid timestamps are normalized to the
    # same UTC ISO 8601 format, allowing chronological
    # string sorting without losing nanoseconds.
    timeline.sort(
        key=lambda item: (
            item["time"] is None,
            item["time"] or "",
        )
    )

    return timeline
