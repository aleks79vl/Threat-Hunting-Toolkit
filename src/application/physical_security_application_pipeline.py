from src.detection.physical.device_policy_detector import (
    DevicePolicy,
)
from src.detection.physical.physical_pipeline import (
    PhysicalPipelineResult,
    run_physical_detection_pipeline,
)
from src.parsers.physical_event_loader import load_physical_events


def _default_physical_policy() -> DevicePolicy:
    return DevicePolicy(
        allowed_device_ids={
            "CORP-USB-001",
        },
        allowed_users={
            "security-admin",
        },
        allowed_hosts={
            "SECURE-WS-01",
        },
        require_serial_number=True,
        require_encrypted_storage=True,
        require_read_only_storage=True,
        require_signed_driver=True,
    )


def run_physical_security_application_pipeline(
    physical_events_file: str,
) -> PhysicalPipelineResult:
    physical_events = load_physical_events(
        physical_events_file
    )

    return run_physical_detection_pipeline(
        physical_events,
        policy=_default_physical_policy(),
    )