from dataclasses import dataclass
from typing import Any

from src.detection.physical.bluetooth_detector import (
    detect_bluetooth_activity,
)
from src.detection.physical.device_policy_detector import (
    DevicePolicy,
    detect_device_policy_violations,
)
from src.detection.physical.hid_detector import (
    detect_hid_attacks,
)
from src.detection.physical.physical_correlation import (
    correlate_physical_events,
)
from src.detection.physical.physical_risk_scoring import (
    calculate_physical_risk_score,
)
from src.detection.physical.storage_detector import (
    detect_storage_activity,
)
from src.detection.physical.usb_detector import (
    detect_usb_devices,
)
from src.detection.physical.workstation_detector import (
    detect_workstation_activity,
)
from src.models.physical_event import PhysicalEvent
from src.models.threat_finding import ThreatFinding


@dataclass
class PhysicalPipelineResult:
    events: list[PhysicalEvent]
    detector_findings: list[ThreatFinding]
    policy_findings: list[ThreatFinding]
    correlation_findings: list[ThreatFinding]
    all_findings: list[ThreatFinding]
    risk_score: int
    statistics: dict[str, Any]


def _create_policy_violation_events(
    events: list[PhysicalEvent],
    policy: DevicePolicy,
) -> list[PhysicalEvent]:
    """
    Convert policy violations into normalized PhysicalEvent objects.

    The correlation engine consumes events rather than ThreatFinding
    objects, so policy violations need a corresponding event representation.
    """

    violation_events: list[PhysicalEvent] = []

    for event in events:
        findings = detect_device_policy_violations(
            [event],
            policy,
        )

        if not findings:
            continue

        violation_events.append(
            PhysicalEvent(
                timestamp=event.timestamp,
                event_type="device_policy_violation",
                device_type=event.device_type,
                device_name=event.device_name,
                device_id=event.device_id,
                vendor=event.vendor,
                serial_number=event.serial_number,
                user=event.user,
                hostname=event.hostname,
                trusted=event.trusted,
                metadata={
                    "policy_findings": [
                        finding.title
                        for finding in findings
                    ]
                },
            )
        )

    return violation_events


def _build_statistics(
    events: list[PhysicalEvent],
    detector_findings: list[ThreatFinding],
    policy_findings: list[ThreatFinding],
    correlation_findings: list[ThreatFinding],
) -> dict[str, Any]:
    event_types: dict[str, int] = {}
    device_types: dict[str, int] = {}
    severity_counts: dict[str, int] = {}

    for event in events:
        event_types[event.event_type] = (
            event_types.get(event.event_type, 0) + 1
        )

        device_type = event.device_type.lower()

        device_types[device_type] = (
            device_types.get(device_type, 0) + 1
        )

    all_findings = (
        detector_findings
        + policy_findings
        + correlation_findings
    )

    for finding in all_findings:
        severity = finding.severity.lower()

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    return {
        "events_parsed": len(events),
        "detector_findings": len(detector_findings),
        "policy_findings": len(policy_findings),
        "correlation_findings": len(
            correlation_findings
        ),
        "total_findings": len(all_findings),
        "event_types": event_types,
        "device_types": device_types,
        "severity_counts": severity_counts,
    }


def run_physical_detection_pipeline(
    events: list[PhysicalEvent],
    *,
    policy: DevicePolicy | None = None,
    trusted_devices: set[str] | None = None,
    blocked_devices: set[str] | None = None,
) -> PhysicalPipelineResult:
    """
    Run all Physical Security detectors and analytical layers.
    """

    policy = policy or DevicePolicy()
    trusted_devices = trusted_devices or set()
    blocked_devices = blocked_devices or set()

    detector_findings: list[ThreatFinding] = []

    detector_findings.extend(
        detect_usb_devices(
            events,
            trusted_devices=trusted_devices,
            blocked_devices=blocked_devices,
        )
    )

    detector_findings.extend(
        detect_hid_attacks(
            events,
            trusted_devices=trusted_devices,
            blocked_devices=blocked_devices,
        )
    )

    detector_findings.extend(
        detect_storage_activity(
            events,
            trusted_devices=trusted_devices,
            blocked_devices=blocked_devices,
        )
    )

    detector_findings.extend(
        detect_bluetooth_activity(
            events,
            trusted_devices=trusted_devices,
            blocked_devices=blocked_devices,
        )
    )

    detector_findings.extend(
        detect_workstation_activity(events)
    )

    policy_findings = detect_device_policy_violations(
        events,
        policy,
    )

    policy_events = _create_policy_violation_events(
        events,
        policy,
    )

    correlation_findings = correlate_physical_events(
        events + policy_events
    )

    all_findings = (
        detector_findings
        + policy_findings
        + correlation_findings
    )

    risk_score = calculate_physical_risk_score(
        all_findings
    )

    statistics = _build_statistics(
        events,
        detector_findings,
        policy_findings,
        correlation_findings,
    )

    statistics["risk_score"] = risk_score

    return PhysicalPipelineResult(
        events=events,
        detector_findings=detector_findings,
        policy_findings=policy_findings,
        correlation_findings=correlation_findings,
        all_findings=all_findings,
        risk_score=risk_score,
        statistics=statistics,
    )