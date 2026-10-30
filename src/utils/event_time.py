import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


ISO_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<offset>Z|[+-]\d{2}:\d{2})?$"
)


def _resolve_local_time(
    local_time: datetime,
    source_timezone: str,
) -> datetime | None:
    """
    Resolve a timezone-naive local timestamp to UTC.

    Reject ambiguous times during DST transitions
    and nonexistent times during clock changes.
    """

    try:
        zone = ZoneInfo(source_timezone)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return None

    candidates = set()

    for fold in (0, 1):
        aware_time = local_time.replace(
            tzinfo=zone,
            fold=fold,
        )

        utc_time = aware_time.astimezone(timezone.utc)

        roundtrip = (
            utc_time
            .astimezone(zone)
            .replace(tzinfo=None)
        )

        if roundtrip == local_time:
            candidates.add(utc_time)

    # Exactly one valid UTC instant is required.
    if len(candidates) != 1:
        return None

    return candidates.pop()


def normalize_event_time(
    value: str | None,
    source_timezone: str | None = None,
) -> str | None:
    """
    Normalize an event timestamp to UTC.

    Preserve up to nine fractional digits.

    Explicit timestamp timezone takes precedence.
    Naive timestamps require a configured source
    timezone and unambiguous local time.
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

        # Work with whole seconds to avoid losing
        # nanoseconds in Python datetime.
        whole_second = event_time.replace(
            microsecond=0
        )

        if event_time.tzinfo is not None:
            utc_time = whole_second.astimezone(
                timezone.utc
            )

        else:
            if not source_timezone:
                return None

            utc_time = _resolve_local_time(
                whole_second,
                source_timezone,
            )

            if utc_time is None:
                return None

        normalized = utc_time.isoformat(
            timespec="seconds"
        )

        fraction = match.group("fraction")

        if fraction is not None:
            normalized = normalized.replace(
                "+00:00",
                f".{fraction}+00:00",
            )

        return normalized

    except (ValueError, OverflowError):
        return None


APACHE_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/"
    r"(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r" (?P<sign>[+-])(?P<offset_hour>\d{2})(?P<offset_minute>\d{2})$"
)

APACHE_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,
    "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9,
    "Oct": 10, "Nov": 11, "Dec": 12,
}


def normalize_apache_time(value: str | None) -> str | None:
    """
    Normalize an Apache access-log timestamp to UTC.

    Preserve up to nine fractional digits.
    Return None for malformed timestamps or invalid offsets.
    """

    if not isinstance(value, str):
        return None

    match = APACHE_TIMESTAMP_PATTERN.fullmatch(value)

    if match is None:
        return None

    parts = match.groupdict()
    month = APACHE_MONTHS.get(parts["month"])

    if month is None:
        return None

    offset_hour = int(parts["offset_hour"])
    offset_minute = int(parts["offset_minute"])

    if offset_hour > 23 or offset_minute > 59:
        return None

    offset = timedelta(
        hours=offset_hour,
        minutes=offset_minute,
    )

    if parts["sign"] == "-":
        offset = -offset

    try:
        event_time = datetime(
            year=int(parts["year"]),
            month=month,
            day=int(parts["day"]),
            hour=int(parts["hour"]),
            minute=int(parts["minute"]),
            second=int(parts["second"]),
            tzinfo=timezone(offset),
        )

        utc_time = event_time.astimezone(timezone.utc)

        normalized = utc_time.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

        fraction = parts["fraction"]

        if fraction is not None:
            normalized += f".{fraction}"

        return f"{normalized}+00:00"

    except (ValueError, OverflowError):
        return None


LINUX_SYSLOG_TIMESTAMP_PATTERN = re.compile(
    r"(?P<month>[A-Z][a-z]{2}) +"
    r"(?P<day>\d{1,2}) +"
    r"(?P<hour>\d{2}):"
    r"(?P<minute>\d{2}):"
    r"(?P<second>\d{2})"
)


def normalize_linux_syslog_time(
    value: str | None,
    source_year: int | None = None,
    source_timezone: str | None = None,
) -> str | None:
    """
    Normalize a traditional Linux syslog timestamp to UTC.

    The source year and timezone must be explicitly provided.

    Reject invalid dates, ambiguous DST timestamps,
    and nonexistent local times.
    """

    if (
        not isinstance(value, str)
        or not isinstance(source_year, int)
        or isinstance(source_year, bool)
        or not isinstance(source_timezone, str)
        or not source_timezone
    ):
        return None

    match = LINUX_SYSLOG_TIMESTAMP_PATTERN.fullmatch(value)

    if match is None:
        return None

    parts = match.groupdict()

    month = APACHE_MONTHS.get(parts["month"])

    if month is None:
        return None

    try:
        local_time = datetime(
            year=source_year,
            month=month,
            day=int(parts["day"]),
            hour=int(parts["hour"]),
            minute=int(parts["minute"]),
            second=int(parts["second"]),
        )

    except ValueError:
        return None

    utc_time = _resolve_local_time(
        local_time,
        source_timezone,
    )

    if utc_time is None:
        return None

    return utc_time.isoformat(timespec="seconds")
