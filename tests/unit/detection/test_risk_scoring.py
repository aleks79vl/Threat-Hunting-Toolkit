import json
import pytest
import re

from src.models.threat_finding import ThreatFinding
from src.correlation.risk_scoring import (
    load_risk_scores,
    calculate_risk_score,
)
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score


def test_load_risk_scores():
    config = load_risk_scores("config/risk_scores.json")

    assert config["severity_scores"]["critical"] == 90
    assert config["bonus_scores"]["unknown_host"] == 20


def test_calculate_risk_score_for_critical_unknown_rdp():
    finding = ThreatFinding(
        title="Unknown host with exposed critical service",
        severity="critical",
        description="Host exposes critical port 3389.",
        source="Threat Correlation Engine",
        ip="192.168.1.77",
        port=3389
    )

    scored_finding = calculate_risk_score(
        finding,
        "config/risk_scores.json"
    )

    assert scored_finding.risk_score == 100


def test_calculate_risk_score_for_high_ssh():
    finding = ThreatFinding(
        title="Critical port exposed",
        severity="high",
        description="Host exposes SSH service.",
        source="critical_port_detector",
        ip="192.168.1.10",
        port=22
    )

    scored_finding = calculate_risk_score(
        finding,
        "config/risk_scores.json"
    )

    assert scored_finding.risk_score == 100


@pytest.mark.parametrize(
    "configured_score, expected_score",
    [
        (42, 42),
        (0, 0),
    ],
)
def test_valid_title_risk_score_is_preserved(
    tmp_path,
    configured_score,
    expected_score,
):
    config_path = tmp_path / "risk_scores.json"
    config_path.write_text(
        json.dumps({
            "severity_scores": {"high": 60},
            "bonus_scores": {},
            "Custom Risk Finding": configured_score,
        }),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Custom Risk Finding",
        severity="high",
        description="Test risk score boundaries",
        source="test",
    )

    result = calculate_risk_score(
        finding,
        str(config_path),
    )

    assert result.risk_score == expected_score


def test_negative_severity_policy_score_is_rejected(tmp_path):
    config_path = tmp_path / "risk_scores.json"
    config_path.write_text(
        json.dumps({
            "severity_scores": {"high": -20},
            "bonus_scores": {},
        }),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Unconfigured Finding",
        severity="high",
        description="Test negative severity score",
        source="test",
        risk_score=17,
    )

    original_state = finding.to_dict()

    with pytest.raises(ValueError, match="risk_scores"):
        calculate_risk_score(
            finding,
            str(config_path),
        )

    assert finding.to_dict() == original_state


def test_global_risk_score_updates_when_rule_changes(tmp_path):
    config_path = tmp_path / "risk_scores.json"

    def write_config(score: int):
        config_path.write_text(
            json.dumps({
                "severity_scores": {"high": 60},
                "bonus_scores": {},
                "Configurable Finding": score,
            }),
            encoding="utf-8",
        )

    finding = ThreatFinding(
        title="Configurable Finding",
        severity="high",
        description="Test rule recalculation",
        source="test",
    )

    write_config(80)

    calculate_risk_score(finding, str(config_path))
    assert finding.risk_score == 80

    # The scoring policy has changed.
    write_config(30)

    calculate_risk_score(finding, str(config_path))

    assert finding.risk_score == 30


def test_risk_scoring_is_independent_of_processing_order():
    def make_finding():
        return ThreatFinding(
            title="Suspicious Linux Process Execution Detected",
            severity="high",
            description="Observed suspicious Linux execution",
            source="Linux Host Detection",
            risk_score=65,
            risk_score_base=65,
            risk_base_sources={"linux_advanced": 65},
            ioc_match=True,
            ioc_confidence="medium",
        )

    # Global scoring first, then IOC.
    first = make_finding()
    calculate_risk_score(first, "config/risk_scores.json")
    apply_ioc_risk_score(first)

    # IOC scoring first, then Global.
    second = make_finding()
    apply_ioc_risk_score(second)
    calculate_risk_score(second, "config/risk_scores.json")

    assert first.risk_score == second.risk_score == 85
    assert first.risk_score_base == second.risk_score_base == 65
    assert first.risk_factors == second.risk_factors == {"ioc": 20}
    assert first.risk_base_sources == second.risk_base_sources
    assert first.scoring_version == second.scoring_version == "1.0"
    assert first.severity == second.severity == "high"


def test_removing_linux_source_recalculates_base_risk():
    finding = ThreatFinding(
        title="Linux Reverse Shell Detected",
        severity="high",
        description="Test source removal",
        source="Linux Host Detection",
        risk_score=95,
        risk_score_base=95,
        risk_base_sources={"linux_advanced": 95},
    )

    calculate_risk_score(finding, "config/risk_scores.json")

    assert finding.risk_score == 95
    assert finding.risk_base_sources["global_policy"] == 60

    # The original Linux evidence is withdrawn.
    finding.risk_base_sources.pop("linux_advanced")

    calculate_risk_score(finding, "config/risk_scores.json")

    assert finding.risk_score_base == 60
    assert finding.risk_score == 60
    assert finding.risk_base_sources == {"global_policy": 60}


def test_global_scoring_rejects_negative_risk_factor():
    finding = ThreatFinding(
        title="Risk Factor Validation",
        severity="high",
        description="Test negative risk factor",
        source="test",
        risk_factors={"ioc": -20},
    )

    with pytest.raises(ValueError, match="risk_factors"):
        calculate_risk_score(
            finding,
            "config/risk_scores.json",
        )


@pytest.mark.parametrize(
    "invalid_sources",
    [
        {"linux_advanced": -5},
        {"linux_advanced": 120},
        {"linux_advanced": "95"},
        {"linux_advanced": True},
        {"": 95},
    ],
)
def test_global_scoring_rejects_invalid_base_sources(
    invalid_sources,
):
    finding = ThreatFinding(
        title="Risk Source Validation",
        severity="high",
        description="Invalid base source test",
        source="test",
        risk_base_sources=invalid_sources.copy(),
    )

    original_sources = finding.risk_base_sources.copy()

    with pytest.raises(ValueError, match="risk_base_sources"):
        calculate_risk_score(
            finding,
            "config/risk_scores.json",
        )

    # Invalid inputs must not modify provenance.
    assert finding.risk_base_sources == original_sources


def test_risk_scoring_policy_fingerprint_is_deterministic(
    tmp_path,
):
    config_path = tmp_path / "risk_scores.json"

    config = {
        "severity_scores": {"high": 60},
        "bonus_scores": {},
        "Custom Finding": 80,
    }

    def make_finding():
        return ThreatFinding(
            title="Custom Finding",
            severity="high",
            description="Test policy fingerprint",
            source="test",
        )

    config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )

    first = calculate_risk_score(
        make_finding(),
        str(config_path),
    )

    assert re.fullmatch(
        r"[0-9a-f]{64}",
        first.scoring_policy_hash,
    )

    # Formatting and JSON key order must not
    # change the fingerprint.
    config_path.write_text(
        json.dumps(config, sort_keys=True, indent=4),
        encoding="utf-8",
    )

    second = calculate_risk_score(
        make_finding(),
        str(config_path),
    )

    assert (
        first.scoring_policy_hash
        == second.scoring_policy_hash
    )

    # A real policy change must change its fingerprint.
    config["Custom Finding"] = 30

    config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )

    third = calculate_risk_score(
        make_finding(),
        str(config_path),
    )

    assert (
        third.scoring_policy_hash
        != first.scoring_policy_hash
    )
    assert third.risk_score == 30


def test_risk_scoring_preserves_detection_severity():
    finding = ThreatFinding(
        title="Unknown host with critical port exposed",
        severity="high",
        description="Unknown host exposes critical port 3389.",
        source="test",
        port=3389,
    )

    result = calculate_risk_score(
        finding,
        "config/risk_scores.json",
    )

    assert result.risk_score == 100
    assert result.severity == "high"
    assert result.scoring_version == "1.0"
    assert result.risk_base_sources["global_policy"] == 100


@pytest.mark.parametrize(
    "section, key, invalid_value",
    [
        ("severity_scores", "high", "60"),
        ("severity_scores", "high", -5),
        ("bonus_scores", "rdp_exposed", -10),
        ("bonus_scores", "rdp_exposed", True),
        ("title", "Custom Finding", 120),
        ("title", "Custom Finding", "80"),
    ],
)
def test_risk_scoring_rejects_invalid_policy_before_mutation(
    tmp_path,
    section,
    key,
    invalid_value,
):
    config = {
        "severity_scores": {"high": 60},
        "bonus_scores": {"rdp_exposed": 20},
        "Custom Finding": 80,
    }

    if section == "title":
        config[key] = invalid_value
    else:
        config[section][key] = invalid_value

    config_path = tmp_path / "invalid_policy.json"
    config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Custom Finding",
        severity="high",
        description="Policy validation test",
        source="test",
        risk_score=17,
    )

    original_state = finding.to_dict()

    with pytest.raises(ValueError, match="risk_scores"):
        calculate_risk_score(
            finding,
            str(config_path),
        )

    assert finding.to_dict() == original_state


def test_valid_policy_accumulated_score_is_capped_at_100(
    tmp_path,
):
    config_path = tmp_path / "risk_scores.json"
    config_path.write_text(
        json.dumps({
            "severity_scores": {"high": 90},
            "bonus_scores": {
                "unknown_host": 20,
                "rdp_exposed": 30,
            },
        }),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Unknown Host",
        severity="high",
        description="Unknown host exposing RDP",
        source="test",
        port=3389,
    )

    result = calculate_risk_score(
        finding,
        str(config_path),
    )

    # 90 + 20 + 30 = 140, capped at 100.
    assert result.risk_score == 100
    assert result.risk_score_base == 100
    assert result.risk_base_sources["global_policy"] == 100

    # Detection severity is independent of risk score.
    assert result.severity == "high"


def test_global_policy_replaces_unattributed_legacy_baseline(
    tmp_path,
):
    from src.intelligence.ioc_risk_scoring import (
        apply_ioc_risk_score,
    )

    config_path = tmp_path / "risk_scores.json"
    config_path.write_text(
        json.dumps({
            "severity_scores": {"high": 60},
            "bonus_scores": {},
            "Standalone IOC Finding": 40,
        }),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Standalone IOC Finding",
        severity="high",
        description="Known malicious indicator",
        source="test",
        risk_score=75,
        ioc_match=True,
        ioc_confidence="high",
    )

    apply_ioc_risk_score(finding)

    result = calculate_risk_score(
        finding,
        str(config_path),
    )

    # Verified global scoring supersedes the unknown base.
    assert result.risk_base_sources == {
        "global_policy": 40,
    }
    assert result.risk_score_base == 40
    assert result.risk_factors["ioc"] == 30
    assert result.risk_score == 70
    assert result.scoring_policy_hash is not None


def test_legacy_to_global_scoring_survives_ioc_withdrawal(
    tmp_path,
):
    from src.intelligence.ioc_risk_scoring import (
        apply_ioc_risk_score,
    )

    config_path = tmp_path / "risk_scores.json"
    config_path.write_text(
        json.dumps({
            "severity_scores": {"high": 60},
            "bonus_scores": {},
            "Standalone IOC Finding": 40,
        }),
        encoding="utf-8",
    )

    finding = ThreatFinding(
        title="Standalone IOC Finding",
        severity="high",
        description="Known malicious indicator",
        source="test",
        risk_score=75,
        ioc_match=True,
        ioc_confidence="high",
    )

    # Stage 1: Unattributed baseline with IOC bonus.
    apply_ioc_risk_score(finding)

    assert finding.risk_score == 100
    assert finding.risk_base_sources == {
        "legacy_unattributed": 75,
    }

    # Stage 2: Verified global policy replaces legacy base.
    calculate_risk_score(finding, str(config_path))

    assert finding.risk_score == 70
    assert finding.risk_score_base == 40
    assert finding.risk_base_sources == {
        "global_policy": 40,
    }

    # Stage 3: IOC evidence is withdrawn.
    finding.ioc_match = False
    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert finding.risk_score_base == 40
    assert "ioc" not in finding.risk_factors
    assert finding.risk_base_sources == {
        "global_policy": 40,
    }
    assert finding.scoring_version == "1.0"
    assert finding.scoring_policy_hash is not None

    # Repeated withdrawal must remain idempotent.
    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert finding.risk_factors == {}
