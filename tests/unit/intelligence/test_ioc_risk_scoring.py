from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.threat_finding import ThreatFinding


def test_apply_ioc_risk_score_high_confidence():

    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="test",
        source="test",
        risk_score=60,
        ioc_match=True,
        ioc_confidence="high"
    )

    enriched = apply_ioc_risk_score(finding)

    assert enriched.risk_score == 90


def test_apply_ioc_risk_score_medium_confidence():

    finding = ThreatFinding(
        title="Known malicious domain",
        severity="medium",
        description="test",
        source="test",
        risk_score=50,
        ioc_match=True,
        ioc_confidence="medium"
    )

    enriched = apply_ioc_risk_score(finding)

    assert enriched.risk_score == 70


def test_apply_ioc_risk_score_max_100():

    finding = ThreatFinding(
        title="Critical IOC",
        severity="critical",
        description="test",
        source="test",
        risk_score=90,
        ioc_match=True,
        ioc_confidence="high"
    )

    enriched = apply_ioc_risk_score(finding)

    assert enriched.risk_score == 100


def test_apply_ioc_risk_score_without_match():

    finding = ThreatFinding(
        title="No IOC",
        severity="low",
        description="test",
        source="test",
        risk_score=40,
        ioc_match=False,
        ioc_confidence="high"
    )

    enriched = apply_ioc_risk_score(finding)

    assert enriched.risk_score == 40