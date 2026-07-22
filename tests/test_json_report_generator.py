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


def test_generate_json_report_contains_mitre_statistics(tmp_path):
    finding = ThreatFinding(
        title="SQL Injection Attempt Detected",
        severity="critical",
        description="test",
        source="test",
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access"
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-30 22:00:00",
        findings=[finding]
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    content = output_file.read_text()

    assert "mitre_statistics" in content
    assert "Initial Access" in content
    assert "T1190" in content

def test_generate_json_report_contains_physical_security(tmp_path):
    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-17 20:00:00",
)

    report.physical_risk_score = 100
    report.physical_statistics = {
        "events_parsed": 5,
        "detector_findings": 13,
        "policy_findings": 4,
        "correlation_findings": 6,
        "total_findings": 23,
        "event_types": {"hid_connect": 1},
        "device_types": {"hid": 2},
        "severity_counts": {"critical": 9, "high": 12},
        }

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    data = json.loads(output_file.read_text())

    assert data["physical_security"]["risk_score"] == 100
    assert data["physical_security"]["statistics"]["events_parsed"] == 5
    assert data["physical_security"]["statistics"]["total_findings"] == 23
    assert data["physical_security"]["statistics"]["device_types"]["hid"] == 2

def test_generate_json_report_has_empty_physical_security_by_default(
    tmp_path,
):
    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-17 20:00:00",
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    data = json.loads(output_file.read_text())

    assert data["physical_security"] == {
        "risk_score": 0,
        "statistics": {},
    }

def test_generate_json_report_contains_web_statistics(tmp_path):
    web_statistics = {
        "total_events": 18,
        "events_by_source": {
            "apache": 3,
            "apache_error": 1,
            "api_gateway": 4,
            "haproxy": 2,
            "nginx": 5,
            "nginx_error": 1,
            "waf_cdn": 2,
        },
    }

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-22 22:00:00",
        web_infrastructure_statistics=web_statistics,
    )

    output_file = tmp_path / "threat_report.json"

    generate_json_report(report, str(output_file))

    data = json.loads(output_file.read_text())

    assert data["web_infrastructure_statistics"] == (
        web_statistics
    )
