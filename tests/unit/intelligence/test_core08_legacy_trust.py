from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


def _finding(value="unverified.core08.invalid"):
    return ThreatFinding(
        title="Web Security Observation",
        severity="medium",
        description=f"Request to {value}",
        source="WAF Security Detector",
        hostname=value,
        ip="198.51.100.25",
        risk_score=40,
        ioc_match=True,
        ioc_type="domain",
        ioc_value=value,
        ioc_confidence="high",
        ioc_source="External Source",
    )


def test_unverified_legacy_scalar_cannot_increase_risk(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    finding = _finding()

    assert finding.ioc_matches == []
    assert ioc_matcher.match_iocs(finding) == []

    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert "ioc" not in finding.risk_factors


def test_unverified_legacy_scalar_cannot_create_correlation(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    finding = _finding()

    assert ioc_matcher.match_iocs(finding) == []

    correlated = correlate_ioc_and_web_findings(
        [finding]
    )

    assert correlated == []


def test_verified_legacy_scalar_remains_supported(
    monkeypatch,
):
    indicator = IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic IOC",
    )

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
    )

    finding = _finding("evil-example.com")

    assert len(ioc_matcher.match_iocs(finding)) == 1

    apply_ioc_risk_score(finding)

    assert finding.risk_factors["ioc"] == 30
    assert finding.risk_score == 70

    correlated = correlate_ioc_and_web_findings(
        [finding]
    )

    assert len(correlated) == 1
    assert correlated[0].ioc_type == "domain"
    assert correlated[0].ioc_value == "evil-example.com"


def test_unverified_legacy_scalar_is_not_counted_as_database_ioc(
    monkeypatch,
):
    from src.reporting.ioc_statistics import generate_ioc_statistics

    monkeypatch.setattr(ioc_matcher, "get_iocs", lambda: [])

    statistics = generate_ioc_statistics([_finding()])

    assert statistics["total_matches"] == 1
    assert statistics["domain"] == 0


def test_verified_legacy_scalar_is_counted_once(monkeypatch):
    from src.reporting.ioc_statistics import generate_ioc_statistics

    indicator = IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic domain IOC",
    )

    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [indicator]
    )

    statistics = generate_ioc_statistics(
        [_finding("evil-example.com")]
    )

    assert statistics["total_matches"] == 1
    assert statistics["domain"] == 1
