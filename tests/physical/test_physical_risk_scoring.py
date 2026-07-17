from src.detection.physical.physical_risk_scoring import (
    calculate_physical_risk_score,
)
from src.models.threat_finding import ThreatFinding


def create_finding(
    severity: str,
    *,
    title: str = "Test Finding",
    source: str = "Test Detector",
) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity=severity,
        description="Test finding",
        source=source,
        recommendation="Review the finding.",
    )


def test_empty_findings_return_zero():
    assert calculate_physical_risk_score([]) == 0


def test_low_finding_score():
    findings = [
        create_finding("low"),
    ]

    assert calculate_physical_risk_score(findings) == 20


def test_medium_finding_score():
    findings = [
        create_finding("medium"),
    ]

    assert calculate_physical_risk_score(findings) == 50


def test_high_finding_score():
    findings = [
        create_finding("high"),
    ]

    assert calculate_physical_risk_score(findings) == 80


def test_critical_finding_score_is_capped():
    findings = [
        create_finding("critical"),
    ]

    assert calculate_physical_risk_score(findings) == 100


def test_multiple_findings_increase_score():
    findings = [
        create_finding("medium"),
        create_finding("medium"),
        create_finding("high"),
        create_finding("high"),
        create_finding("high"),
    ]

    score = calculate_physical_risk_score(findings)

    assert score > 68
    assert score <= 100


def test_policy_violation_adds_risk():
    baseline = [
        create_finding("medium"),
    ]

    policy_findings = [
        create_finding(
            "medium",
            source="Device Policy Detector",
        ),
    ]

    baseline_score = calculate_physical_risk_score(
        baseline,
    )
    policy_score = calculate_physical_risk_score(
        policy_findings,
    )

    assert policy_score > baseline_score


def test_correlation_adds_risk():
    baseline = [
        create_finding("high"),
    ]

    correlation_findings = [
        create_finding(
            "high",
            source="Physical Correlation Engine",
        ),
    ]

    baseline_score = calculate_physical_risk_score(
        baseline,
    )
    correlation_score = calculate_physical_risk_score(
        correlation_findings,
    )

    assert correlation_score > baseline_score


def test_complete_attack_chain_returns_maximum_risk():
    findings = [
        create_finding(
            "critical",
            title=(
                "Multi-Stage Physical Attack Chain Detected"
            ),
            source="Physical Correlation Engine",
        ),
    ]

    assert calculate_physical_risk_score(findings) == 100


def test_unknown_severity_does_not_break_scoring():
    findings = [
        create_finding("unknown"),
    ]

    assert calculate_physical_risk_score(findings) == 0


def test_score_never_exceeds_one_hundred():
    findings = [
        create_finding(
            "critical",
            title=(
                "Multi-Stage Physical Attack Chain Detected"
            ),
            source="Physical Correlation Engine",
        )
        for _ in range(10)
    ]

    assert calculate_physical_risk_score(findings) == 100