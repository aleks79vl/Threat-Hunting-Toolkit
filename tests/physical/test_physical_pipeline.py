from pathlib import Path

from src.detection.physical.device_policy_detector import (
    DevicePolicy,
)
from src.detection.physical.physical_pipeline import (
    run_physical_detection_pipeline,
)
from src.parsers.physical_event_loader import (
    load_physical_events,
)


SAMPLE_FILE = Path(
    "data/raw/physical/sample_physical_events.json"
)


def test_physical_event_loader():
    events = load_physical_events(SAMPLE_FILE)

    assert len(events) == 5
    assert events[0].event_type == "hid_connect"
    assert events[0].device_id == "HID-DUCKY-001"


def test_complete_physical_pipeline():
    events = load_physical_events(SAMPLE_FILE)

    policy = DevicePolicy(
        allowed_device_ids={"CORP-USB-001"},
        allowed_users={"security-admin"},
        allowed_hosts={"SECURE-WS-01"},
        require_serial_number=True,
        require_encrypted_storage=True,
        require_read_only_storage=True,
        require_signed_driver=True,
    )

    result = run_physical_detection_pipeline(
        events,
        policy=policy,
    )

    assert result.events == events
    assert result.all_findings
    assert result.policy_findings
    assert result.correlation_findings
    assert result.risk_score > 0

    assert result.statistics["events_parsed"] == 5
    assert result.statistics["total_findings"] == len(
        result.all_findings
    )


def test_pipeline_detects_full_attack_chain():
    events = load_physical_events(SAMPLE_FILE)

    policy = DevicePolicy(
        allowed_device_ids={"CORP-USB-001"},
    )

    result = run_physical_detection_pipeline(
        events,
        policy=policy,
    )

    titles = {
        finding.title
        for finding in result.all_findings
    }

    assert (
        "Multi-Stage Physical Attack Chain Detected"
        in titles
    )


def test_empty_pipeline_input():
    result = run_physical_detection_pipeline([])

    assert result.events == []
    assert result.all_findings == []
    assert result.risk_score == 0
    assert result.statistics["events_parsed"] == 0