import json
from pathlib import Path

from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.json_report_generator import generate_json_report


def test_generate_json_report_creates_file(tmp_path):
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes Remote Desktop service.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        recommendation="Investigate host and restrict RDP access."
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 14:00:00",
        findings=[finding]
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(
        report,
        str(output_file)
    )

    assert output_file.exists()


def test_generate_json_report_contains_summary(tmp_path):
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
        generated_at="2026-06-26 14:00:00",
        findings=[finding]
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    data = json.loads(output_file.read_text())

    assert "summary" in data
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["critical"] == 1


def test_generate_json_report_contains_findings(tmp_path):
    finding = ThreatFinding(
        title="Unknown host",
        severity="high",
        description="Host is not listed in whitelist.",
        source="unknown_ip_detector",
        ip="192.168.1.77"
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 14:00:00",
        findings=[finding]
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    data = json.loads(output_file.read_text())

    assert "findings" in data
    assert data["findings"][0]["ip"] == "192.168.1.77"
    assert data["findings"][0]["severity"] == "high"