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

def test_executive_summary_contains_linux_execution_statistics():
    report = ThreatReport(title="Threat Hunting Report",
        generated_at="2026-07-11 18:30:00",findings=[],timeline=[],)

    report.linux_execution_statistics = {
        "total_executions": 13,
        "suspicious_executions": 3,
        "unique_executables": 2,
        "top_executables": [
            ("/bin/bash", 2),
            ("telnet", 1),
        ],
        "top_users": [
            ("admin", 5),
            ("alex", 2),
        ],
        "mitre_statistics": [
            ("T1059.004", 2),
            ("T1021", 1),
        ],}

    summary = generate_executive_summary(report)

    assert "Advanced Linux Execution Summary" in summary
    assert "Total executions: 13" in summary
    assert "Suspicious executions: 3" in summary
    assert "Unique executables: 2" in summary


def test_executive_summary_contains_top_linux_values():
    report = ThreatReport(title="Threat Hunting Report",
        generated_at="2026-07-11 18:30:00",findings=[],timeline=[],)

    report.linux_execution_statistics = {
        "total_executions": 13,
        "suspicious_executions": 3,
        "unique_executables": 2,
        "top_executables": [
            ("/bin/bash", 2),
        ],
        "top_users": [
            ("admin", 5),
        ],
        "mitre_statistics": [
            ("T1059.004", 2),
        ],
    }

    summary = generate_executive_summary(report)

    assert "Top executable: /bin/bash" in summary
    assert "Most active user: admin" in summary
    assert "Top MITRE technique: T1059.004" in summary


def test_executive_summary_handles_empty_linux_execution_statistics():
    report = ThreatReport(title="Threat Hunting Report",
        generated_at="2026-07-11 18:30:00",findings=[],timeline=[],)

    report.linux_execution_statistics = {}

    summary = generate_executive_summary(report)

    assert "Total executions: 0" in summary
    assert "Suspicious executions: 0" in summary
    assert "Unique executables: 0" in summary
    assert "Top executable: N/A" in summary
    assert "Most active user: N/A" in summary
    assert "Top MITRE technique: N/A" in summary


def test_executive_summary_handles_missing_linux_execution_statistics():
    report = ThreatReport(title="Threat Hunting Report",
        generated_at="2026-07-11 18:30:00",findings=[],timeline=[],)

    summary = generate_executive_summary(report)

    assert "Advanced Linux Execution Summary" in summary
    assert "Total executions: 0" in summary
    assert "Top executable: N/A" in summary