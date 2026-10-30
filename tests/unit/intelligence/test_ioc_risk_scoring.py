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


def test_ioc_risk_scoring_is_idempotent():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Test repeated IOC scoring",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_type="ip",
        ioc_value="203.0.113.10",
        ioc_confidence="high",
    )

    first_result = apply_ioc_risk_score(finding)

    assert first_result.risk_score == 70

    second_result = apply_ioc_risk_score(finding)

    assert second_result.risk_score == 70


def test_ioc_risk_scoring_preserves_base_and_factor():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="IOC factor provenance",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_confidence="high",
    )

    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 40
    assert finding.risk_factors["ioc"] == 30
    assert finding.risk_score == 70


def test_ioc_confidence_change_recalculates_bonus():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Changed confidence",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_confidence="high",
    )

    apply_ioc_risk_score(finding)
    assert finding.risk_score == 70

    finding.ioc_confidence = "medium"

    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 40
    assert finding.risk_factors["ioc"] == 20
    assert finding.risk_score == 60


def test_removed_ioc_match_removes_its_risk_factor():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="IOC evidence removal",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_confidence="high",
    )

    apply_ioc_risk_score(finding)
    assert finding.risk_score == 70

    # The IOC evidence is no longer considered valid.
    finding.ioc_match = False
    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 40
    assert "ioc" not in finding.risk_factors
    assert finding.risk_score == 40


def test_ioc_scoring_is_idempotent_after_serialization():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="IOC serialization test",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_confidence="high",
    )

    apply_ioc_risk_score(finding)

    payload = finding.to_dict()

    assert payload["risk_score"] == 70
    assert payload["risk_score_base"] == 40
    assert payload["risk_factors"] == {"ioc": 30}

    restored = ThreatFinding(**payload)

    apply_ioc_risk_score(restored)

    assert restored.risk_score == 70
    assert restored.risk_factors == {"ioc": 30}
