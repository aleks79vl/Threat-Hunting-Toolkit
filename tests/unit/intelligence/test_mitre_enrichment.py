from src.models.threat_finding import ThreatFinding
from src.correlation.mitre_enrichment import enrich_finding_with_mitre


def test_enrich_failed_logon():
    finding = ThreatFinding(
        title="Windows Failed Logon Detected",
        severity="medium",
        description="test",
        source="Test"
    )

    enriched = enrich_finding_with_mitre(finding)

    assert enriched.technique == "T1110"
    assert enriched.technique_name == "Brute Force"
    assert enriched.tactic == "Credential Access"


def test_enrich_unknown_detection():
    finding = ThreatFinding(
        title="Unknown Detection",
        severity="low",
        description="test",
        source="Test"
    )

    enriched = enrich_finding_with_mitre(finding)

    assert enriched.technique == "Unknown"
    assert enriched.technique_name == "Unknown"
    assert enriched.tactic == "Unknown"