from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class PhysicalDetectionContext:
    """
    Shared context for all Physical Security detectors.

    The context stores normalized physical-security telemetry,
    device trust data, detector findings, policy violations,
    correlation results and the final physical risk score.
    """

    connected_usb_devices: List[Dict] = field(default_factory=list)
    connected_hid_devices: List[Dict] = field(default_factory=list)
    connected_storage_devices: List[Dict] = field(default_factory=list)
    connected_bluetooth_devices: List[Dict] = field(default_factory=list)

    workstation_events: List[Dict] = field(default_factory=list)

    trusted_devices: Set[str] = field(default_factory=set)
    blocked_devices: Set[str] = field(default_factory=set)

    device_history: List[Dict] = field(default_factory=list)

    policy_violations: List[Dict] = field(default_factory=list)
    correlation_findings: List[Dict] = field(default_factory=list)
    alerts: List[Dict] = field(default_factory=list)

    physical_risk_score: int = 0