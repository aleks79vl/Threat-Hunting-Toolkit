from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.intelligence import ioc_loader, ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


def _empty_feed(monkeypatch):
    monkeypatch.setattr(ioc_loader, "get_iocs", lambda: [])
    monkeypatch.setattr(ioc_matcher, "get_iocs", lambda: [])


def _unverified_record():
    return {
        "ioc_type": "domain",
        "value": "unverified.core08.invalid",
        "confidence": "high",
        "source": "Unverified External Source",
        "description": "Unverified evidence",
    }


def _unverified_finding():
    return ThreatFinding(
        title="API Session Observation",
        severity="medium",
        description="No malicious network indicator observed",
        source="WAF Security Detector",
        ip="198.51.100.25",
        risk_score=40,
        ioc_match=True,
        ioc_type="session_id_hash",
        ioc_value="hmac-sha256:synthetic-session",
        ioc_source="WAF Security Detector",
        ioc_matches=[_unverified_record()],
    )


def test_unverified_embedded_ioc_cannot_increase_risk(monkeypatch):
    _empty_feed(monkeypatch)
    finding = _unverified_finding()

    assert ioc_matcher.match_iocs(finding) == []

    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert "ioc" not in finding.risk_factors


def test_unverified_embedded_ioc_cannot_create_correlation(monkeypatch):
    _empty_feed(monkeypatch)
    finding = _unverified_finding()

    assert ioc_matcher.match_iocs(finding) == []

    correlated = correlate_ioc_and_web_findings([finding])

    assert correlated == []


def test_unverified_matches_cannot_erase_external_identity(
    monkeypatch,
):
    _empty_feed(monkeypatch)

    finding = ThreatFinding(
        title="External IOC Observation",
        severity="high",
        description="External detector finding",
        source="External Detector",
        ioc_match=True,
        ioc_type="domain",
        ioc_value="external.example.invalid",
        ioc_source="External Detector",
        ioc_matches=[{
            "ioc_type": "domain",
            "value": "external.example.invalid",
            "source": "External Detector",
            "confidence": "medium",
            "description": "Unverified record",
        }],
    )

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert finding.ioc_match is True
    assert finding.ioc_type == "domain"
    assert finding.ioc_value == "external.example.invalid"
    assert finding.ioc_source == "External Detector"
    assert finding.ioc_matches == []


def test_locally_matched_feed_ioc_still_scores(monkeypatch):
    indicator = IOC(
        value="evil-example.com",
        ioc_type="domain",
        confidence="high",
        source="CORE-08 Test Feed",
        description="Synthetic domain IOC",
    )

    monkeypatch.setattr(
        ioc_loader, "get_iocs", lambda: [indicator]
    )
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [indicator]
    )

    finding = ThreatFinding(
        title="Web Security Observation",
        severity="medium",
        description="Connection to evil-example.com",
        source="WAF Security Detector",
        hostname="evil-example.com",
        risk_score=40,
    )

    ioc_matcher.enrich_finding_with_ioc(finding)
    apply_ioc_risk_score(finding)

    assert finding.ioc_match is True
    assert len(finding.ioc_matches) == 1
    assert finding.risk_factors["ioc"] == 30
    assert finding.risk_score == 70
