import pytest

from src.utils import event_time


def test_linux_syslog_time_normalizes_with_explicit_context():
    result = event_time.normalize_linux_syslog_time(
        "Jul  7 10:00:01",
        source_year=2026,
        source_timezone="Asia/Jerusalem",
    )

    assert result == "2026-07-07T07:00:01+00:00"


@pytest.mark.parametrize(
    "source_year,source_timezone",
    [
        (None, "Asia/Jerusalem"),
        (2026, None),
        (None, None),
    ],
)
def test_linux_syslog_time_requires_year_and_timezone(
    source_year,
    source_timezone,
):
    result = event_time.normalize_linux_syslog_time(
        "Jun 29 09:00:15",
        source_year=source_year,
        source_timezone=source_timezone,
    )

    assert result is None


@pytest.mark.parametrize(
    "timestamp",
    [
        "Mar  8 02:30:00",
        "Nov  1 01:30:00",
    ],
)
def test_linux_syslog_time_rejects_dst_uncertainty(timestamp):
    result = event_time.normalize_linux_syslog_time(
        timestamp,
        source_year=2026,
        source_timezone="America/New_York",
    )

    assert result is None


def test_linux_syslog_time_rejects_invalid_date():
    result = event_time.normalize_linux_syslog_time(
        "Feb 30 09:00:15",
        source_year=2026,
        source_timezone="UTC",
    )

    assert result is None
