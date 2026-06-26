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