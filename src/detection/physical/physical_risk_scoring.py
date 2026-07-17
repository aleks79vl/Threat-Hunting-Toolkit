from src.models.threat_finding import ThreatFinding


SEVERITY_SCORES = {
    "low": 20,
    "medium": 50,
    "high": 80,
    "critical": 100,
}

POLICY_SOURCE = "Device Policy Detector"
CORRELATION_SOURCE = "Physical Correlation Engine"
FULL_CHAIN_TITLE = "Multi-Stage Physical Attack Chain Detected"


def calculate_physical_risk_score(
    findings: list[ThreatFinding],
) -> int:
    """
    Calculate the overall Physical Security risk score.

    Scoring factors:
    - average severity score;
    - number of findings;
    - presence of critical findings;
    - device-policy violations;
    - correlated attack findings;
    - complete multi-stage physical attack chain.
    """

    if not findings:
        return 0

    severity_scores = [
        SEVERITY_SCORES.get(
            finding.severity.lower(),
            0,
        )
        for finding in findings
    ]

    score = sum(severity_scores) / len(severity_scores)

    critical_count = sum(
        1
        for finding in findings
        if finding.severity.lower() == "critical"
    )

    policy_violation_count = sum(
        1
        for finding in findings
        if finding.source == POLICY_SOURCE
    )

    correlation_count = sum(
        1
        for finding in findings
        if finding.source == CORRELATION_SOURCE
    )

    full_chain_detected = any(
        finding.title == FULL_CHAIN_TITLE
        for finding in findings
    )

    if len(findings) >= 5:
        score += 5

    if len(findings) >= 10:
        score += 5

    if critical_count >= 1:
        score += 5

    if critical_count >= 3:
        score += 5

    if policy_violation_count >= 1:
        score += 5

    if policy_violation_count >= 3:
        score += 5

    if correlation_count >= 1:
        score += 5

    if correlation_count >= 3:
        score += 5

    if full_chain_detected:
        score += 15

    return min(round(score), 100)