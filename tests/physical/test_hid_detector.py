from datetime import datetime

from src.detection.physical.hid_detector import detect_hid_attacks

from src.models.physical_event import PhysicalEvent

def create_hid_event(

    device_id: str,

    *,

    event_type: str = "hid_connect",

    device_type: str = "HID",

    device_name: str = "Generic Keyboard",

    trusted: bool = False,

    input_rate: float | None = None,

    command: str | None = None,

) -> PhysicalEvent:

    return PhysicalEvent(

        timestamp=datetime.now(),

        event_type=event_type,

        device_type=device_type,

        device_name=device_name,

        device_id=device_id,

        hostname="WORKSTATION-01",

        user="alex",

        trusted=trusted,

        input_rate=input_rate,

        command=command,

    )

def test_unknown_hid_device_detection():

    findings = detect_hid_attacks(

        [create_hid_event("HID-UNKNOWN-001")]

    )

    titles = [finding.title for finding in findings]

    assert "Unknown HID Device Connected" in titles

def test_trusted_hid_device_is_not_unknown():

    event = create_hid_event("HID-TRUSTED-001")

    findings = detect_hid_attacks(

        [event],

        trusted_devices={"HID-TRUSTED-001"},

    )

    titles = [finding.title for finding in findings]

    assert "Unknown HID Device Connected" not in titles

def test_blocked_hid_device_detection():

    event = create_hid_event("HID-BLOCKED-001")

    findings = detect_hid_attacks(

        [event],

        blocked_devices={"HID-BLOCKED-001"},

    )

    assert len(findings) == 1

    assert findings[0].title == "Blocked HID Device Connected"

    assert findings[0].severity == "critical"

def test_rubber_ducky_detection():

    event = create_hid_event(

        "HID-DUCKY-001",

        device_name="USB Rubber Ducky",

    )

    findings = detect_hid_attacks([event])

    titles = [finding.title for finding in findings]

    assert "Potential BadUSB or Rubber Ducky Device" in titles

def test_fast_hid_input_detection():

    event = create_hid_event(

        "HID-FAST-001",

        event_type="hid_input",

        input_rate=25.0,

    )

    findings = detect_hid_attacks([event])

    titles = [finding.title for finding in findings]

    assert "Abnormally Fast HID Input Detected" in titles

def test_suspicious_powershell_command_detection():

    event = create_hid_event(

        "HID-CMD-001",

        event_type="hid_input",

        command="powershell -enc ZQBjAGgAbwA=",

    )

    findings = detect_hid_attacks([event])

    titles = [finding.title for finding in findings]

    assert "Suspicious Command Entered by HID Device" in titles

def test_repeated_hid_connections_detection():

    events = [

        create_hid_event("HID-REPEAT-001"),

        create_hid_event("HID-REPEAT-001"),

        create_hid_event("HID-REPEAT-001"),

    ]

    findings = detect_hid_attacks(events)

    titles = [finding.title for finding in findings]

    assert "Repeated HID Device Connections" in titles

def test_non_hid_event_is_ignored():

    event = PhysicalEvent(

        timestamp=datetime.now(),

        event_type="usb_insert",

        device_type="USB",

        device_name="USB Storage",

        device_id="USB-001",

    )

    assert detect_hid_attacks([event]) == []