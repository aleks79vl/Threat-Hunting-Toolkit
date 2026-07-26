from datetime import datetime

from src.models.physical_event import PhysicalEvent


def test_physical_event_creation():
    event = PhysicalEvent(
        timestamp=datetime.now(),
        event_type="usb_insert",
        device_type="USB",
        device_name="Kingston DataTraveler",
        device_id="USB12345",
    )

    assert event.device_type == "USB"
    assert event.event_type == "usb_insert"
    assert event.trusted is False