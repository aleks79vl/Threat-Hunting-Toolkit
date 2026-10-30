from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR


def normalize_packet_time(
    value: str,
) -> tuple[Decimal, str] | None:
    """Convert a TShark Unix epoch timestamp to UTC ISO 8601."""

    try:
        timestamp = Decimal(value.strip())

        if not timestamp.is_finite():
            return None

        if (
            timestamp < Decimal("-62135596800")
            or timestamp >= Decimal("253402300800")
        ):
            return None

        seconds = int(
            timestamp.to_integral_value(rounding=ROUND_FLOOR)
        )

        event_time = (
            datetime(1970, 1, 1, tzinfo=timezone.utc)
            + timedelta(seconds=seconds)
        )

        iso_time = event_time.isoformat(timespec="seconds")
        fraction = timestamp - Decimal(seconds)

        if fraction:
            fractional_part = (
                format(fraction, "f")
                .split(".", 1)[1]
                .rstrip("0")
            )

            iso_time = iso_time.replace(
                "+00:00",
                f".{fractional_part}+00:00",
            )

        return timestamp, iso_time

    except (
        InvalidOperation,
        ValueError,
        OverflowError,
        AttributeError,
        TypeError,
    ):
        return None