from src.models.threat_finding import ThreatFinding


IOC_CONFIDENCE_BONUSES = {
    "high": 30,
    "medium": 20,
    "low": 10,
}


def apply_ioc_risk_score(
    finding: ThreatFinding,
) -> ThreatFinding:
    """
    Apply the current IOC confidence factor without
    accumulating the same bonus on repeated calls.
    """

    if not finding.ioc_match:
        if "ioc" in finding.risk_factors:
            del finding.risk_factors["ioc"]

            if finding.risk_score_base is not None:
                total_score = (
                    finding.risk_score_base
                    + sum(finding.risk_factors.values())
                )

                finding.risk_score = max(
                    0,
                    min(100, total_score),
                )

        return finding

    confidence = (finding.ioc_confidence or "").lower()

    bonus = IOC_CONFIDENCE_BONUSES.get(
        confidence,
        0,
    )

    if finding.risk_score_base is None:
        finding.risk_score_base = finding.risk_score

    finding.risk_factors["ioc"] = bonus

    total_score = (
        finding.risk_score_base
        + sum(finding.risk_factors.values())
    )

    finding.risk_score = max(
        0,
        min(100, total_score),
    )

    return finding
