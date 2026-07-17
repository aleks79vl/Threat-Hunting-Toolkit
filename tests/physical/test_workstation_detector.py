from datetime import datetime, timedelta

from src.detection.physical.workstation_detector import (
    detect_workstation_activity,
)
from src.models.physical_event import PhysicalEvent


BASE_TIME = datetime(2026, 7, 15, 12, 0, 0)


def create_event(
    event_type: str,
    *,
    minutes: int = 0,
    hostname: str = "WORKSTATION-01",
    user: str = "alex",
    previous_user: str | None = None,
    device_type: str = "workstation",
    device_name: str = "Corporate Workstation",
    device_id: str = "WS-001",
) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        event_type=event_type,
        device_type=device_type,
        device_name=device_name,
        device_id=device_id,
        hostname=hostname,
        user=user,
        previous_user=previous_user,
    )


def test_remote_logon_detection():
    findings = detect_workstation_activity(
        [create_event("remote_logon")]
    )

    assert any(
        finding.title == "Remote Workstation Logon Detected"
        for finding in findings
    )


def test_console_logon_outside_working_hours():
    event = PhysicalEvent(
        timestamp=datetime(2026, 7, 15, 2, 30, 0),
        event_type="console_logon",
        device_type="workstation",
        device_name="Corporate Workstation",
        device_id="WS-001",
        hostname="WORKSTATION-01",
        user="alex",
    )

    findings = detect_workstation_activity([event])

    assert any(
        finding.title == "Console Logon Outside Working Hours"
        for finding in findings
    )


def test_unlock_after_usb_connection():
    events = [
        create_event(
            "usb_insert",
            device_type="USB",
            device_name="Unknown USB Device",
            device_id="USB-001",
        ),
        create_event(
            "workstation_unlock",
            minutes=2,
        ),
    ]

    findings = detect_workstation_activity(events)

    assert any(
        finding.title
        == "Workstation Unlocked After Physical Device Connection"
        for finding in findings
    )


def test_session_user_change():
    event = create_event(
        "session_switch",
        user="admin",
        previous_user="alex",
    )

    findings = detect_workstation_activity([event])

    assert any(
        finding.title == "Workstation Session User Changed"
        for finding in findings
    )


def test_frequent_unlock_detection():
    events = [
        create_event("workstation_unlock", minutes=index)
        for index in range(5)
    ]

    findings = detect_workstation_activity(
        events,
        unlock_threshold=5,
    )

    assert any(
        finding.title == "Frequent Workstation Unlock Activity"
        for finding in findings
    )


def test_normal_console_logon_is_not_flagged():
    findings = detect_workstation_activity(
        [create_event("console_logon")]
    )

    assert findings == []


def test_irrelevant_event_is_ignored():
    findings = detect_workstation_activity(
        [
            create_event(
                "storage_copy",
                device_type="external_storage",
            )
        ]
    )

    assert findings == []