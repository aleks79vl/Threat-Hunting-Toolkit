import json

from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport


def test_threat_report_creation():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes Remote Desktop service.",
        source="correlation",
        ip="192.168.1.77",
        port=3389
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 13:00:00",
        findings=[finding]
    )

    assert report.title == "Threat Hunting Report"
    assert report.total_findings() == 1


def test_threat_report_summary():
    findings = [
        ThreatFinding(
            title="Critical finding",
            severity="critical",
            description="Critical issue.",
            source="test"
        ),
        ThreatFinding(
            title="High finding",
            severity="high",
            description="High issue.",
            source="test"
        ),
        ThreatFinding(
            title="Another critical finding",
            severity="critical",
            description="Another critical issue.",
            source="test"
        )
    ]

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 13:00:00",
        findings=findings
    )

    summary = report.summary()

    assert summary["total_findings"] == 3
    assert summary["critical"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 0
    assert summary["low"] == 0


def test_threat_report_to_dict():
    finding = ThreatFinding(
        title="Unknown host",
        severity="high",
        description="Host not found in whitelist.",
        source="unknown_ip_detector",
        ip="192.168.1.77"
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 13:00:00",
        findings=[finding]
    )

    data = report.to_dict()

    assert data["title"] == "Threat Hunting Report"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["ip"] == "192.168.1.77"


def test_threat_report_to_json():
    finding = ThreatFinding(
        title="Critical port exposed",
        severity="critical",
        description="RDP is exposed.",
        source="critical_port_detector",
        ip="192.168.1.77",
        port=3389
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 13:00:00",
        findings=[finding]
    )

    parsed = json.loads(report.to_json())

    assert parsed["title"] == "Threat Hunting Report"
    assert parsed["summary"]["critical"] == 1
    assert parsed["findings"][0]["port"] == 3389