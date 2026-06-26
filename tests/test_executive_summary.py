from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.executive_summary import generate_executive_summary


def test_generate_executive_summary_contains_title():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        risk_score=160
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 17:00:00",
        findings=[finding]
    )

    summary = generate_executive_summary(report)

    assert "Threat Hunting Summary" in summary
    assert "Analysis completed successfully." in summary


def test_generate_executive_summary_counts_findings():
    findings = [
        ThreatFinding(
            title="Critical finding",
            severity="critical",
            description="Critical issue.",
            source="test",
            risk_score=160
        ),
        ThreatFinding(
            title="High finding",
            severity="high",
            description="High issue.",
            source="test",
            risk_score=80
        )
    ]

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 17:00:00",
        findings=findings
    )

    summary = generate_executive_summary(report)

    assert "Total findings: 2" in summary
    assert "Critical findings: 1" in summary
    assert "High findings: 1" in summary
    assert "Highest risk score: 160" in summary


def test_generate_executive_summary_recommends_investigation():
    finding = ThreatFinding(
        title="Critical finding",
        severity="critical",
        description="Critical issue.",
        source="test",
        risk_score=160
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 17:00:00",
        findings=[finding]
    )

    summary = generate_executive_summary(report)

    assert "Immediate investigation is recommended" in summary