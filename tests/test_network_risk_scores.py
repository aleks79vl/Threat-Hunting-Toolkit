from src.correlation.risk_scoring import calculate_risk_score
from src.models.threat_finding import ThreatFinding


RISK_CONFIG = "config/risk_scores.json"


def create_finding(title: str) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity="medium",
        description="test",
        source="Unit Test",
        recommendation="Investigate",
    )


def test_unknown_network_ip_risk_score():
    finding = calculate_risk_score(
        create_finding("Unknown Network IP Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 50


def test_network_ioc_match_risk_score():
    finding = calculate_risk_score(
        create_finding("Network IOC Match Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 85


def test_possible_arp_spoofing_risk_score():
    finding = calculate_risk_score(
        create_finding("Possible ARP Spoofing Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 85


def test_correlated_mitm_activity_risk_score():
    finding = calculate_risk_score(
        create_finding("Possible MITM Activity Correlated"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 100