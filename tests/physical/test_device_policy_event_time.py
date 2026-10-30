from datetime import datetime, timedelta, timezone

import pytest

from src.models.physical_event import PhysicalEvent
from src.detection.physical.device_policy_detector import (
    DevicePolicy,
    detect_device_policy_violations,
)


@pytest.mark.parametrize(
    "timestamp, expected",
    [
        (
            datetime(
                2026, 7, 16, 12, 0,
                tzinfo=timezone(timedelta(hours=3)),
            ),
            "2026-07-16T09:00:00+00:00",
        ),
        (
            datetime(2026, 7, 16, 12, 0),
            None,
        ),
    ],
)


def test_device_policy_preserves_event_time(
    timestamp,
    expected,
):
    event = PhysicalEvent(
        timestamp=timestamp,
        event_type="usb_insert",
        device_type="hid",
        device_name="Test Device",
        device_id="BLOCKED-001",
    )

    policy = DevicePolicy(
        blocked_device_ids={"BLOCKED-001"},
    )

    findings = detect_device_policy_violations(
        [event],
        policy,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen == expected
    assert finding.last_seen == expected