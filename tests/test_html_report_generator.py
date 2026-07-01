from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.html_report_generator import generate_html_report


def test_generate_html_report_creates_file(tmp_path):
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        hostname="unknown-host",
        port=3389,
        risk_score=160,
        recommendation="Investigate host and restrict RDP access."
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 17:30:00",
        findings=[finding],
        timeline=[]
    )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    assert output_file.exists()


def test_generate_html_report_contains_title(tmp_path):
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
        generated_at="2026-06-26 17:30:00",
        findings=[finding],
        timeline=[]
    )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text()

    assert "Threat Hunting Report" in content
    assert "Executive Summary" in content
    assert "Detected Threats" in content


def test_generate_html_report_contains_finding_data(tmp_path):
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        hostname="unknown-host",
        port=3389,
        risk_score=160,
        recommendation="Investigate host and restrict RDP access."
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 17:30:00",
        findings=[finding],
        timeline=[]
    )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text()

    assert "192.168.1.77" in content
    assert "3389" in content
    assert "160" in content
    assert "Investigate host" in content


def test_generate_html_report_contains_timeline(tmp_path):
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        hostname="unknown-host",
        port=3389,
        risk_score=160
    )

    timeline = [
        {
            "time": "2026-06-26 18:30:00",
            "event": "Unknown host with exposed RDP",
            "severity": "critical",
            "ip": "192.168.1.77",
            "port": 3389,
            "risk_score": 160,
            "source": "Threat Correlation Engine"
        }
    ]

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-06-26 18:30:00",
        findings=[finding],
        timeline=timeline
    )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text()

    assert "Threat Timeline" in content
    assert "2026-06-26 18:30:00" in content
    assert "Threat Correlation Engine" in content


def test_generate_html_report_contains_mitre_statistics(tmp_path):
    finding = ThreatFinding(
        title="SQL Injection Attempt Detected",
        severity="critical",
        description="test",
        source="test",
        ip="203.0.113.10",
        hostname="web-server",
        port=80,
        risk_score=90,
        recommendation="Investigate SQL injection attempt.",
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access"
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-01 16:45:00",
        findings=[finding],
        timeline=[]
        )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text()

    assert "MITRE ATT&amp;CK Statistics" in content or "MITRE ATT&CK Statistics" in content
    assert "Unique tactics" in content
    assert "Unique techniques" in content
    assert "Initial Access" in content or "1" in content


def test_generate_html_report_contains_ioc_intelligence(tmp_path):
    finding = ThreatFinding(
        title="Known malicious IP detected",
        severity="high",
        description="test",
        source="Unit Test",
        ip="185.220.101.1",
        hostname="host",
        port=80,
        risk_score=90,
        recommendation="Investigate",
        ioc_match=True,
        ioc_type="ip",
        ioc_value="185.220.101.1",
        ioc_confidence="high",
        ioc_source="Local IOC Database",
        ioc_description="Known Tor exit node"
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-01 22:30:00",
        findings=[finding],
        timeline=[]
    )

    output_file = tmp_path / "threat_report.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text()

    assert "IOC Intelligence" in content
    assert "IOC Match" in content
    assert "185.220.101.1" in content
    assert "Local IOC Database" in content