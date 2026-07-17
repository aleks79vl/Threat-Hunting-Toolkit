from src.detection.physical.physical_detection_context import (
    PhysicalDetectionContext,
)


def test_context_creation():
    context = PhysicalDetectionContext()

    assert context.connected_usb_devices == []
    assert context.connected_hid_devices == []
    assert context.connected_storage_devices == []
    assert context.connected_bluetooth_devices == []

    assert context.workstation_events == []

    assert context.trusted_devices == set()
    assert context.blocked_devices == set()

    assert context.device_history == []

    assert context.policy_violations == []
    assert context.correlation_findings == []
    assert context.alerts == []

    assert context.physical_risk_score == 0