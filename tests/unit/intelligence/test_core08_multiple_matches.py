from dataclasses import asdict

from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


def _iocs():
    return [
        IOC(
            value="203.0.113.99",
            ioc_type="ip",
            source="CORE-08 Test Feed",
            confidence="medium",
            description="Test IP",
        ),
        IOC(
            value="evil-example.com",
            ioc_type="domain",
            source="CORE-08 Test Feed",
            confidence="high",
            description="Test domain",
        ),
        IOC(
            value="/shell.php",
            ioc_type="url",
            source="CORE-08 Test Feed",
            confidence="low",
            description="Test URL",
        ),
    ]


def _finding():
    return ThreatFinding(
        title="Web Security Observation",
        severity="medium",
        description="Request to /shell.php detected",
        source="CORE-08 Test",
        ip="203.0.113.99",
        hostname="evil-example.com",
        risk_score=40,
    )


def test_match_iocs_returns_all_matches_independent_of_feed_order(
    monkeypatch,
):
    indicators = _iocs()

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: indicators,
    )

    first = ioc_matcher.match_iocs(_finding())

    indicators.reverse()

    second = ioc_matcher.match_iocs(_finding())

    expected = [
        ("domain", "evil-example.com"),
        ("ip", "203.0.113.99"),
        ("url", "/shell.php"),
    ]

    assert [
        (ioc.ioc_type, ioc.value)
        for ioc in first
    ] == expected

    assert [
        (ioc.ioc_type, ioc.value)
        for ioc in second
    ] == expected


def test_match_ioc_returns_primary_by_confidence(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        _iocs,
    )

    result = ioc_matcher.match_ioc(_finding())

    assert result is not None
    assert result.ioc_type == "domain"
    assert result.value == "evil-example.com"
    assert result.confidence == "high"


def test_enrichment_preserves_all_matches_and_serialization(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        _iocs,
    )

    finding = _finding()

    enriched = ioc_matcher.enrich_finding_with_ioc(finding)

    assert enriched is finding
    assert enriched.ioc_match is True

    assert enriched.ioc_type == "domain"
    assert enriched.ioc_value == "evil-example.com"
    assert enriched.ioc_confidence == "high"

    assert len(enriched.ioc_matches) == 3

    expected = [
        asdict(_iocs()[1]),
        asdict(_iocs()[0]),
        asdict(_iocs()[2]),
    ]

    assert enriched.ioc_matches == expected

    payload = enriched.to_dict()

    assert payload["ioc_matches"] == expected

    restored = ThreatFinding(**payload)

    assert restored.ioc_matches == expected
    assert restored.ioc_value == "evil-example.com"


def test_multiple_matches_do_not_accumulate_risk_bonus(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        _iocs,
    )

    finding = _finding()

    ioc_matcher.enrich_finding_with_ioc(finding)
    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 40
    assert finding.risk_factors["ioc"] == 30
    assert finding.risk_score == 70

    ioc_matcher.enrich_finding_with_ioc(finding)
    apply_ioc_risk_score(finding)

    assert len(finding.ioc_matches) == 3
    assert finding.risk_factors == {"ioc": 30}
    assert finding.risk_score == 70


def test_non_database_ioc_identity_is_not_overwritten(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [],
    )

    finding = ThreatFinding(
        title="API Session Anomaly",
        severity="high",
        description="Abnormal session activity",
        source="API Security Detector",
        ioc_match=True,
        ioc_type="session_id_hash",
        ioc_value="hmac-sha256:synthetic-test-identity",
        ioc_source="API Security Detector",
    )

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert finding.ioc_match is True
    assert finding.ioc_type == "session_id_hash"
    assert (
        finding.ioc_value
        == "hmac-sha256:synthetic-test-identity"
    )
    assert finding.ioc_source == "API Security Detector"
