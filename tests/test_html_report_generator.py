from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.html_report_generator import generate_html_report

def create_report() -> ThreatReport:

    return ThreatReport(title="Threat Hunting Report",
        generated_at="2026-07-11 18:00:00",
        findings=[],
        timeline=[],)


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

def test_html_report_contains_linux_execution_statistics(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 13,
        "suspicious_executions": 3,
        "unique_executables": 2,
        "top_executables": [
            ("/bin/bash", 2),
            ("telnet", 1),
        ],
        "top_users": [
            ("root", 2),
            ("alex", 1),
        ],
        "mitre_statistics": [
            ("T1059.004", 2),
            ("T1021", 1),
        ],
    }

    output_file = tmp_path / "report.html"

    generate_html_report(
        report,
        str(output_file),
    )

    html = output_file.read_text(encoding="utf-8")

    assert "Advanced Linux Execution Statistics" in html
    assert "Total executions analyzed:" in html
    assert "Suspicious executions:" in html
    assert "Unique executables:" in html

    assert "/bin/bash" in html
    assert "telnet" in html
    assert "root" in html
    assert "alex" in html
    assert "T1059.004" in html
    assert "T1021" in html


def test_html_report_handles_empty_linux_execution_statistics(
    tmp_path,
):
    report = create_report()

    report.linux_execution_statistics = {}

    output_file = tmp_path / "report.html"

    generate_html_report(
        report,
        str(output_file),
    )

    html = output_file.read_text(encoding="utf-8")

    assert "Advanced Linux Execution Statistics" in html
    assert "No executable data available" in html
    assert "No user data available" in html
    assert "No MITRE data available" in html

def test_html_report_contains_linux_execution_summary(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 13,
        "suspicious_executions": 3,
        "unique_executables": 1,
        "top_executables": [
            ("/bin/bash", 1),
        ],
        "top_users": [
            ("admin", 5),
        ],
        "mitre_statistics": [
            ("T1059.004", 2),
        ],
    }

    output_file = tmp_path / "report.html"

    generate_html_report(
        report,
        str(output_file),
    )

    html = output_file.read_text(encoding="utf-8")

    assert "Advanced Linux Execution Summary" in html
    assert "Total executions: 13" in html
    assert "Suspicious executions: 3" in html
    assert "Top executable: /bin/bash" in html
    assert "Most active user: admin" in html
    assert "Top MITRE technique: T1059.004" in html
