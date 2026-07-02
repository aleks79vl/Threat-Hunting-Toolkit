from src.models.threat_finding import ThreatFinding


def apply_ioc_risk_score(finding: ThreatFinding) -> ThreatFinding:
    """
    Increase risk score if finding has IOC match.
    """

    if not getattr(finding, "ioc_match", False):
        return finding

    confidence = getattr(finding, "ioc_confidence", "").lower()

    bonus = 0

    if confidence == "high":
        bonus = 30
    elif confidence == "medium":
        bonus = 20
    elif confidence == "low":
        bonus = 10

    finding.risk_score = min(
        100,
        finding.risk_score + bonus
    )

    return finding