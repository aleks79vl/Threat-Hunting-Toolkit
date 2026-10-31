import pytest

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


def test_standalone_ioc_scoring_records_algorithm_version():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Standalone IOC scoring",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_type="ip",
        ioc_value="203.0.113.10",
        ioc_confidence="high",
    )

    result = apply_ioc_risk_score(finding)

    assert result.risk_score == 70
    assert result.risk_score_base == 40
    assert result.risk_factors == {"ioc": 30}

    # Every scored finding must identify its algorithm version.
    assert result.scoring_version == "1.0"


def test_ioc_scoring_rejects_negative_risk_factor():
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Invalid risk factor",
        source="test",
        risk_score=40,
        ioc_match=True,
        ioc_confidence="high",
        risk_factors={"invalid_bonus": -10},
    )

    with pytest.raises(ValueError, match="risk_factors"):
        apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert finding.risk_factors == {"invalid_bonus": -10}


@pytest.mark.parametrize("ioc_match", [True, False])
def test_standalone_ioc_scoring_rejects_invalid_base_sources(
    ioc_match,
):
    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Invalid base source",
        source="test",
        risk_score=40,
        ioc_match=ioc_match,
        ioc_confidence="high",
        risk_base_sources={"linux_advanced": "95"},
    )

    original_state = finding.to_dict()

    with pytest.raises(ValueError, match="risk_base_sources"):
        apply_ioc_risk_score(finding)

    # Invalid provenance must not partially mutate the finding.
    assert finding.to_dict() == original_state


@pytest.mark.parametrize(
    "risk_score, risk_score_base",
    [
        (150, None),
        (-1, None),
        (True, None),
        ("40", None),
        (40, 150),
        (40, -5),
        (40, True),
        (40, "40"),
    ],
)
def test_standalone_ioc_rejects_invalid_base_scores(
    risk_score,
    risk_score_base,
):
    finding = ThreatFinding(
        title="IOC Risk Validation",
        severity="high",
        description="Invalid standalone risk baseline",
        source="test",
        risk_score=risk_score,
        risk_score_base=risk_score_base,
        ioc_match=True,
        ioc_confidence="high",
    )

    original_state = finding.to_dict()

    with pytest.raises(ValueError, match="risk_score"):
        apply_ioc_risk_score(finding)

    assert finding.to_dict() == original_state


def test_standalone_ioc_marks_unattributed_legacy_baseline():
    finding = ThreatFinding(
        title="Standalone IOC Finding",
        severity="high",
        description="Known malicious indicator",
        source="test",
        risk_score=75,
        ioc_match=True,
        ioc_confidence="high",
    )

    result = apply_ioc_risk_score(finding)

    assert result.risk_score_base == 75
    assert result.risk_score == 100
    assert result.risk_factors["ioc"] == 30

    # The baseline exists, but its origin is unverified.
    assert result.risk_base_sources == {
        "legacy_unattributed": 75,
    }

    # Standalone IOC does not load a global scoring policy.
    assert result.scoring_policy_hash is None


@pytest.mark.parametrize(
    "stale_base",
    [None, 40],
)
def test_ioc_scoring_uses_registered_base_sources(
    stale_base,
):
    finding = ThreatFinding(
        title="Linux Threat With IOC",
        severity="high",
        description="Advanced Linux detection",
        source="linux",
        risk_score=20,
        risk_score_base=stale_base,
        risk_base_sources={
            "linux_advanced": 80,
        },
        ioc_match=True,
        ioc_confidence="high",
    )

    result = apply_ioc_risk_score(finding)

    assert result.risk_score_base == 80
    assert result.risk_score == 100
    assert result.risk_factors["ioc"] == 30
    assert result.risk_base_sources == {
        "linux_advanced": 80,
    }

    assert "legacy_unattributed" not in result.risk_base_sources

    assert result.scoring_version == "1.0"
    assert result.severity == "high"


@pytest.mark.parametrize("stale_base", [None, 40])
@pytest.mark.parametrize(
    "existing_factors",
    [
        {},
        {"ioc": 30},
    ],
)
def test_ioc_withdrawal_reconciles_registered_base_sources(
    stale_base,
    existing_factors,
):
    finding = ThreatFinding(
        title="Linux Threat After IOC Withdrawal",
        severity="high",
        description="Linux detection with withdrawn IOC",
        source="linux",
        risk_score=20,
        risk_score_base=stale_base,
        risk_base_sources={
            "linux_advanced": 80,
        },
        risk_factors=existing_factors.copy(),
        ioc_match=False,
    )

    result = apply_ioc_risk_score(finding)

    assert result.risk_score_base == 80
    assert result.risk_score == 80

    assert "ioc" not in result.risk_factors

    assert result.risk_base_sources == {
        "linux_advanced": 80,
    }

    assert result.scoring_version == "1.0"
    assert result.severity == "high"

    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 80
    assert finding.risk_score == 80
    assert finding.risk_factors == {}
