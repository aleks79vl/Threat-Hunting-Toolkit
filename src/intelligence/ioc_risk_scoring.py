from src.models.threat_finding import ThreatFinding
from src.models.risk_scoring_contract import (
    RISK_SCORING_VERSION,
    validate_risk_factors,
    validate_risk_base_sources,
    validate_risk_score_value,
)


IOC_CONFIDENCE_BONUSES = {
    "high": 30,
    "medium": 20,
    "low": 10,
}


def apply_ioc_risk_score(
    finding: ThreatFinding,
) -> ThreatFinding:
    """
    Apply IOC confidence scoring without accumulating
    duplicate contributions or losing baseline provenance.
    """

    validate_risk_factors(finding.risk_factors)
    validate_risk_base_sources(finding.risk_base_sources)

    validate_risk_score_value(
        finding.risk_score,
        field_name="risk_score",
    )

    if finding.risk_score_base is not None:
        validate_risk_score_value(
            finding.risk_score_base,
            field_name="risk_score_base",
        )

    verified_sources = {
        source_id: score
        for source_id, score in finding.risk_base_sources.items()
        if source_id != "legacy_unattributed"
    }

    if verified_sources:
        finding.risk_base_sources.pop(
            "legacy_unattributed",
            None,
        )

        finding.risk_score_base = max(
            verified_sources.values()
        )

    elif finding.risk_base_sources:
        finding.risk_score_base = max(
            finding.risk_base_sources.values()
        )

    if not finding.ioc_match:
        had_ioc_factor = "ioc" in finding.risk_factors

        finding.risk_factors.pop("ioc", None)

        if (
            finding.risk_score_base is not None
            and (
                finding.risk_base_sources
                or had_ioc_factor
            )
        ):
            total_score = (
                finding.risk_score_base
                + sum(finding.risk_factors.values())
            )

            finding.risk_score = max(
                0,
                min(100, total_score),
            )

        finding.scoring_version = RISK_SCORING_VERSION

        return finding

    confidence = (finding.ioc_confidence or "").lower()

    bonus = IOC_CONFIDENCE_BONUSES.get(
        confidence,
        0,
    )

    if finding.risk_score_base is None:
        finding.risk_score_base = finding.risk_score

    if not finding.risk_base_sources:
        finding.risk_base_sources["legacy_unattributed"] = (
            finding.risk_score_base
        )

    finding.risk_factors["ioc"] = bonus

    total_score = (
        finding.risk_score_base
        + sum(finding.risk_factors.values())
    )

    finding.risk_score = max(
        0,
        min(100, total_score),
    )

    finding.scoring_version = RISK_SCORING_VERSION

    return finding
