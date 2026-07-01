from src.models.threat_finding import ThreatFinding
from src.reporting.mitre_statistics import generate_mitre_statistics


def test_generate_mitre_statistics_counts_tactics():
    findings = [
        ThreatFinding(
            title="SQL Injection Attempt Detected",
            severity="critical",
            description="test",
            source="test",
            tactic="Initial Access",
            technique="T1190"
        ),
        ThreatFinding(
            title="XSS Attempt Detected",
            severity="high",
            description="test",
            source="test",
            tactic="Initial Access",
            technique="T1189"
        ),
        ThreatFinding(
            title="Suspicious PowerShell Process",
            severity="high",
            description="test",
            source="test",
            tactic="Execution",
            technique="T1059.001"
        ),
    ]

    stats = generate_mitre_statistics(findings)

    assert stats["tactics"]["Initial Access"] == 2
    assert stats["tactics"]["Execution"] == 1


def test_generate_mitre_statistics_counts_techniques():
    findings = [
        ThreatFinding(
            title="Windows Failed Logon Detected",
            severity="medium",
            description="test",
            source="test",
            tactic="Credential Access",
            technique="T1110"
        ),
        ThreatFinding(
            title="Windows Failed Logon Detected",
            severity="medium",
            description="test",
            source="test",
            tactic="Credential Access",
            technique="T1110"
        ),
    ]

    stats = generate_mitre_statistics(findings)

    assert stats["techniques"]["T1110"] == 2


def test_generate_mitre_statistics_handles_unknown():
    findings = [
        ThreatFinding(
            title="Unknown Finding",
            severity="low",
            description="test",
            source="test"
        )
    ]

    stats = generate_mitre_statistics(findings)

    assert stats["tactics"]["Unknown"] == 1
    assert stats["techniques"]["Unknown"] == 1