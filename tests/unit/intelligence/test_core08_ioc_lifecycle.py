from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


def _ioc():
    return IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic domain IOC",
    )


def _finding():
    return ThreatFinding(
        title="Web Security Observation",
        severity="medium",
        description="Connection to evil-example.com",
        source="WAF Security Detector",
        ip="198.51.100.10",
        hostname="evil-example.com",
        risk_score=40,
    )


def test_revoked_database_ioc_removes_stale_evidence_and_bonus(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_ioc()]
    )

    finding = _finding()

    ioc_matcher.enrich_finding_with_ioc(finding)
    apply_ioc_risk_score(finding)

    assert finding.ioc_match is True
    assert len(finding.ioc_matches) == 1
    assert finding.risk_score == 70

    # The IOC is no longer present in the database.
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    ioc_matcher.enrich_finding_with_ioc(finding)
    apply_ioc_risk_score(finding)

    assert finding.ioc_match is False
    assert finding.ioc_matches == []
    assert finding.ioc_type == ""
    assert finding.ioc_value == ""
    assert "ioc" not in finding.risk_factors
    assert finding.risk_score == 40


def test_session_identity_and_database_ioc_receive_correct_bonus(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_ioc()]
    )

    finding = _finding()
    finding.ioc_match = True
    finding.ioc_type = "session_id_hash"
    finding.ioc_value = "hmac-sha256:synthetic-session"
    finding.ioc_source = "API Security Detector"

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert finding.ioc_type == "session_id_hash"
    assert finding.ioc_value == "hmac-sha256:synthetic-session"
    assert len(finding.ioc_matches) == 1

    apply_ioc_risk_score(finding)

    assert finding.risk_score_base == 40
    assert finding.risk_factors["ioc"] == 30
    assert finding.risk_score == 70


def test_revocation_preserves_external_identity(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: [_ioc()]
    )

    finding = _finding()
    finding.ioc_match = True
    finding.ioc_type = "session_id_hash"
    finding.ioc_value = "hmac-sha256:synthetic-session"
    finding.ioc_source = "API Security Detector"

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert len(finding.ioc_matches) == 1

    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert finding.ioc_matches == []
    assert finding.ioc_match is True
    assert finding.ioc_type == "session_id_hash"
    assert finding.ioc_value == "hmac-sha256:synthetic-session"
    assert finding.ioc_source == "API Security Detector"


def test_legacy_scalar_ioc_without_database_enrichment_is_preserved(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher, "get_iocs", lambda: []
    )

    finding = _finding()
    finding.ioc_match = True
    finding.ioc_type = "domain"
    finding.ioc_value = "legacy.example.test"
    finding.ioc_source = "Legacy Detector"

    ioc_matcher.enrich_finding_with_ioc(finding)

    assert finding.ioc_match is True
    assert finding.ioc_type == "domain"
    assert finding.ioc_value == "legacy.example.test"
    assert finding.ioc_matches == []


def test_session_identity_alone_does_not_receive_database_ioc_bonus():
    finding = ThreatFinding(
        title="API Session Anomaly",
        severity="high",
        description="Abnormal session activity",
        source="API Security Detector",
        risk_score=40,
        ioc_match=True,
        ioc_type="session_id_hash",
        ioc_value="hmac-sha256:synthetic-session",
        ioc_confidence="high",
        ioc_source="API Security Detector",
    )

    apply_ioc_risk_score(finding)

    assert finding.ioc_match is True
    assert finding.risk_score == 40
    assert "ioc" not in finding.risk_factors
