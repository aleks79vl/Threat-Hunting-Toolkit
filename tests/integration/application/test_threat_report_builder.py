from src.application.threat_report_builder import (
    build_threat_report,
)
from src.models.threat_finding import ThreatFinding


def test_build_threat_report_populates_all_report_sections():
    findings = [
        ThreatFinding(
            title="Test Finding",
            severity="high",
            description="Synthetic finding for report testing.",
            source="Test Source",
            ip="198.51.100.250",
            risk_score=70,
        ),
    ]

    report = build_threat_report(
        findings=findings,
        network_statistics={
            "total_network_events": 10,
        },
        linux_statistics={
            "total_events": 5,
        },
        linux_execution_statistics={
            "total_executions": 3,
        },
        web_infrastructure_statistics={
            "total_events": 7,
        },
        physical_statistics={
            "events_parsed": 2,
        },
        physical_risk_score=80,
        generated_at="2026-07-25 13:00:00",
    )

    assert report.title == "Threat Hunting Report"
    assert report.generated_at == "2026-07-25 13:00:00"
    assert report.findings == findings
    assert report.network_statistics["total_network_events"] == 10
    assert report.linux_statistics["total_events"] == 5
    assert report.linux_execution_statistics["total_executions"] == 3
    assert report.web_infrastructure_statistics["total_events"] == 7
    assert report.physical_statistics["events_parsed"] == 2
    assert report.physical_risk_score == 80

    assert len(report.timeline) == 1
    assert report.timeline[0]["event"] == "Test Finding"
    assert report.timeline[0]["risk_score"] == 70