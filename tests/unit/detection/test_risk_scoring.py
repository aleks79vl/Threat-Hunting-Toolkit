from src.models.threat_finding import ThreatFinding
from src.correlation.risk_scoring import (
    load_risk_scores,
    calculate_risk_score,
)


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

    assert scored_finding.risk_score == 160


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
