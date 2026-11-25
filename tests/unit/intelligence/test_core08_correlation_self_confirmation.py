from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


def _indicator():
    return IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Audit Feed",
        confidence="high",
    )


def _original_web_finding():
    return ThreatFinding(
        title="WAF Detection",
        severity="high",
        description="Observed web request",
        source="WAF Security Detector",
        ip="198.51.100.25",
        hostname="evil-example.com",
        ioc_match=True,
        ioc_type="domain",
        ioc_value="evil-example.com",
        ioc_confidence="high",
        ioc_source="CORE-08 Audit Feed",
    )


def test_correlation_narrative_cannot_confirm_itself(monkeypatch):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_indicator()]
    )

    finding = ThreatFinding(
        title="Known Malicious IOC Observed in Web Activity",
        severity="high",
        description=(
            "IOC 'domain' with value 'evil-example.com' "
            "matched 1 web finding(s)."
        ),
        source="IOC + Web Correlation",
        ip="198.51.100.25",
        risk_score=40,
        ioc_match=True,
        ioc_type="domain",
        ioc_value="evil-example.com",
        ioc_confidence="high",
        ioc_source="CORE-08 Audit Feed",
    )

    assert ioc_matcher.match_iocs(finding) == []

    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert "ioc" not in finding.risk_factors


def test_correlation_requires_live_upstream_evidence(monkeypatch):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_indicator()]
    )

    original = _original_web_finding()
    results = correlate_ioc_and_web_findings([original])

    assert len(results) == 1

    correlated = results[0]
    correlated.risk_score = 40

    assert len(ioc_matcher.match_iocs(correlated)) == 1

    apply_ioc_risk_score(correlated)

    assert correlated.risk_score == 70
    assert correlated.risk_factors["ioc"] == 30

    # Remove the structured observation from the source.
    original.hostname = ""

    assert ioc_matcher.match_iocs(correlated) == []

    apply_ioc_risk_score(correlated)

    assert correlated.risk_score == 40
    assert "ioc" not in correlated.risk_factors


def test_correlation_runtime_sources_are_not_serialized(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_indicator()]
    )

    results = correlate_ioc_and_web_findings(
        [_original_web_finding()]
    )

    assert len(results) == 1

    correlated = results[0]
    payload = correlated.to_dict()

    assert "_core08_correlation_sources" not in payload

    restored = ThreatFinding(**payload)

    assert ioc_matcher.match_iocs(restored) == []


def test_correlation_respects_feed_revocation(monkeypatch):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_indicator()]
    )

    results = correlate_ioc_and_web_findings(
        [_original_web_finding()]
    )

    assert len(results) == 1
    assert len(ioc_matcher.match_iocs(results[0])) == 1

    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    assert ioc_matcher.match_iocs(results[0]) == []
