from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding
from src.reporting.ioc_statistics import generate_ioc_statistics


def test_unverified_ioc_collection_does_not_inflate_statistics(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [],
    )

    finding = ThreatFinding(
        title="API Session Observation",
        severity="medium",
        description="No known IOC observed",
        source="WAF Security Detector",
        ioc_match=True,
        ioc_type="session_id_hash",
        ioc_value="hmac-sha256:synthetic-session",
        ioc_matches=[
            {
                "ioc_type": "domain",
                "value": "unverified.core08.invalid",
                "confidence": "high",
                "source": "Unverified External Source",
                "description": "Unverified indicator",
            }
        ],
    )

    statistics = generate_ioc_statistics([finding])

    # Preserve existing matched-finding semantics.
    assert statistics["total_matches"] == 1

    # An unverified record must not count as a database IOC.
    assert statistics["domain"] == 0


def test_serialized_ioc_revocation_restores_original_risk(
    monkeypatch,
):
    indicator = IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic domain IOC",
    )

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
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

    assert finding.risk_score == 70

    # Serialize and reconstruct the finding.
    restored = ThreatFinding(**finding.to_dict())

    # IOC removed from current feed.
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [],
    )

    ioc_matcher.enrich_finding_with_ioc(restored)

    assert restored.ioc_matches == []
    assert restored.ioc_match is False

    apply_ioc_risk_score(restored)

    assert restored.risk_score_base == 40
    assert restored.risk_score == 40
    assert "ioc" not in restored.risk_factors
