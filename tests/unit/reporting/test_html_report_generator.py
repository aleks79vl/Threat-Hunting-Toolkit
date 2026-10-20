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

def test_html_report_contains_web_infrastructure_statistics(
    tmp_path,
):
    report = create_report()

    report.web_infrastructure_statistics = {
        "total_events": 30,
        "events_by_source": {
            "api_gateway": 3,
            "nginx": 2,
            "waf_cdn": 3,
        },
    }

    output_file = tmp_path / "report.html"

    generate_html_report(report, str(output_file))

    html = output_file.read_text(encoding="utf-8")

    assert "Web Infrastructure Telemetry" in html
    assert "Total normalized web events:" in html
    assert "30" in html
    assert "api_gateway" in html
    assert "nginx" in html
    assert "waf_cdn" in html

def test_html_report_contains_physical_security_data(tmp_path):
    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-24 20:00:00",
        physical_risk_score=100,
        physical_statistics={
            "events_parsed": 5,
            "detector_findings": 13,
            "policy_findings": 4,
            "correlation_findings": 6,
            "total_findings": 23,
            "event_types": {"hid_connect": 1},
            "device_types": {"hid": 2},
            "severity_counts": {
                "critical": 9,
                "high": 12,
            },
        },
    )

    output_file = tmp_path / "report.html"

    generate_html_report(report, str(output_file))

    html = output_file.read_text(encoding="utf-8")

    assert "Physical Security" in html
    assert "100/100" in html
    assert "Critical Risk" in html
    assert "hid_connect" in html
    assert "hid" in html

def test_html_report_escapes_hostname(tmp_path):
    malicious_hostname = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Host",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname=malicious_hostname,
        port=443,
        risk_score=80,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "security_test_report.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_hostname not in html_content

def test_html_report_escapes_finding_title(tmp_path):
    malicious_title = "<script>alert(1)</script>"

    finding = ThreatFinding(
        title=malicious_title,
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "security_test_report.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content
    assert malicious_title not in html_content

def test_html_report_escapes_timeline_event(tmp_path):
    malicious_event = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-14 08:00:00",
                "event": malicious_event,
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_event not in html_content

def test_html_report_escapes_linux_username(tmp_path):
    malicious_username = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [
            ("/bin/bash", 1),
        ],
        "top_users": [
            (malicious_username, 1),
        ],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_username not in html_content

def test_html_report_escapes_ioc_source(tmp_path):
    malicious_ioc_source = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Malicious IOC Detected",
        severity="high",
        description="IOC HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        ioc_match=True,
        ioc_type="ip",
        ioc_value="192.168.1.100",
        ioc_confidence="high",
        ioc_source=malicious_ioc_source,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "ioc_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ioc_source not in html_content

def test_html_report_escapes_mitre_technique_name(tmp_path):
    malicious_technique_name = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="MITRE HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name=malicious_technique_name,
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "mitre_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_technique_name not in html_content

def test_html_report_escapes_finding_ip(tmp_path):
    malicious_ip = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious IP",
        severity="high",
        description="IP HTML Injection Security Test",
        source="security_test",
        ip=malicious_ip,
        hostname="test-server",
        port=443,
        risk_score=80,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "ip_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ip not in html_content

def test_html_report_escapes_finding_recommendation(tmp_path):
    malicious_recommendation = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="Recommendation HTML Injection Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        recommendation=malicious_recommendation,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "recommendation_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_recommendation not in html_content

def test_html_report_escapes_timeline_source(tmp_path):
    malicious_source = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-14 08:00:00",
                "event": "Suspicious Activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": malicious_source,
            }
        ],
    )

    output_file = tmp_path / "timeline_source_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_source not in html_content

def test_html_report_escapes_timeline_ip(tmp_path):
    malicious_ip = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-14 08:00:00",
                "event": "Suspicious Activity",
                "severity": "high",
                "ip": malicious_ip,
                "port": 443,
                "risk_score": 80,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_ip_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ip not in html_content

def test_html_report_escapes_timeline_time(tmp_path):
    malicious_time = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-14 08:00:00",
        findings=[],
        timeline=[
            {
                "time": malicious_time,
                "event": "Suspicious Activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_time_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_time not in html_content

def test_html_report_escapes_timeline_severity(tmp_path):
    malicious_severity = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-15 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-15 08:00:00",
                "event": "Suspicious Activity",
                "severity": malicious_severity,
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_severity_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    escaped_severity = (
        "&lt;IMG SRC=X ONERROR=ALERT(1)&gt;"
    )

    assert escaped_severity in html_content
    assert malicious_severity.upper() not in html_content

def test_html_report_escapes_timeline_port(tmp_path):
    malicious_port = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-15 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-15 08:00:00",
                "event": "Suspicious Activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": malicious_port,
                "risk_score": 80,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_port_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_port not in html_content

def test_html_report_escapes_timeline_risk_score(tmp_path):
    malicious_score = "<img src=x onerror=alert(1)>"

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-15 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-15 08:00:00",
                "event": "Suspicious Activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": malicious_score,
                "source": "security_test",
            }
        ],
    )

    output_file = tmp_path / "timeline_risk_score_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_score not in html_content

def test_html_report_escapes_linux_executable(tmp_path):
    malicious_executable = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [
            (malicious_executable, 1),
        ],
        "top_users": [],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_executable_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_executable not in html_content

def test_html_report_escapes_linux_mitre_technique(tmp_path):
    malicious_technique = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [
            (malicious_technique, 1),
        ],
    }

    output_file = tmp_path / "linux_mitre_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_technique not in html_content

def test_html_report_escapes_linux_executable_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [
            ("/bin/bash", malicious_count),
        ],
        "top_users": [],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_executable_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_user_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [],
        "top_users": [
            ("root", malicious_count),
        ],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_user_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_mitre_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 1,
        "unique_executables": 1,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [
            ("T1059.004", malicious_count),
        ],
    }

    output_file = tmp_path / "linux_mitre_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_network_protocol(tmp_path):
    malicious_protocol = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.network_statistics = {
        "protocols": {
            malicious_protocol: 1,
        }
    }

    output_file = tmp_path / "network_protocol_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_protocol not in html_content

def test_html_report_escapes_network_protocol_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.network_statistics = {
        "protocols": {
            "TCP": malicious_count,
        }
    }

    output_file = tmp_path / "network_protocol_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_action(tmp_path):
    malicious_action = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {
            malicious_action: 1,
        },
        "statuses": {},
        "users": {},
        "source_ips": {},
    }

    output_file = tmp_path / "linux_action_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_action not in html_content

def test_html_report_escapes_linux_action_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {
            "execve": malicious_count,
        },
        "statuses": {},
        "users": {},
        "source_ips": {},
    }

    output_file = tmp_path / "linux_action_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_status(tmp_path):
    malicious_status = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {
            malicious_status: 1,
        },
        "users": {},
        "source_ips": {},
    }

    output_file = tmp_path / "linux_status_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_status not in html_content

def test_html_report_escapes_linux_status_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {
            "success": malicious_count,
        },
        "users": {},
        "source_ips": {},
    }

    output_file = tmp_path / "linux_status_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_statistics_user(tmp_path):
    malicious_user = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {},
        "users": {
            malicious_user: 1,
        },
        "source_ips": {},
    }

    output_file = tmp_path / "linux_statistics_user_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_user not in html_content

def test_html_report_escapes_linux_statistics_user_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {},
        "users": {
            "root": malicious_count,
        },
        "source_ips": {},
    }

    output_file = tmp_path / "linux_statistics_user_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_source_ip(tmp_path):
    malicious_ip = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {},
        "users": {},
        "source_ips": {
            malicious_ip: 1,
        },
    }

    output_file = tmp_path / "linux_source_ip_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ip not in html_content

def test_html_report_escapes_linux_source_ip_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "actions": {},
        "statuses": {},
        "users": {},
        "source_ips": {
            "192.168.1.100": malicious_count,
        },
    }

    output_file = tmp_path / "linux_source_ip_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_finding_technique(tmp_path):
    malicious_technique = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.technique = malicious_technique

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_technique_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_technique not in html_content

def test_html_report_escapes_finding_tactic(tmp_path):
    malicious_tactic = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.tactic = malicious_tactic

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_tactic_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_tactic not in html_content

def test_html_report_escapes_finding_ioc_match(tmp_path):
    malicious_ioc_match = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.ioc_match = malicious_ioc_match

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_ioc_match_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ioc_match not in html_content

def test_html_report_escapes_finding_ioc_type(tmp_path):
    malicious_ioc_type = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.ioc_type = malicious_ioc_type

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_ioc_type_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ioc_type not in html_content

def test_html_report_escapes_finding_ioc_value(tmp_path):
    malicious_ioc_value = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.ioc_value = malicious_ioc_value

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_ioc_value_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_ioc_value not in html_content

def test_html_report_escapes_finding_ioc_confidence(tmp_path):
    malicious_confidence = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.ioc_confidence = malicious_confidence

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_ioc_confidence_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_confidence not in html_content

def test_html_report_escapes_finding_severity(tmp_path):
    malicious_severity = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity=malicious_severity,
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_severity_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;IMG SRC=X ONERROR=ALERT(1)&gt;" in html_content
    assert malicious_severity.upper() not in html_content

def test_html_report_escapes_finding_port(tmp_path):
    malicious_port = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.port = malicious_port

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_port_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_port not in html_content

def test_html_report_escapes_finding_risk_score(tmp_path):
    malicious_risk_score = "<img src=x onerror=alert(1)>"

    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="HTML Injection Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-host",
        port=443,
        risk_score=80,
    )

    finding.risk_score = malicious_risk_score

    report = ThreatReport(
        title="Security Test Report",
        generated_at="2026-10-16 10:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "finding_risk_score_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_risk_score not in html_content

def test_html_report_escapes_physical_device_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "device_types": {
            "camera": malicious_count,
        },
        "event_types": {},
    }

    output_file = tmp_path / "physical_device_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>camera</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_event_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "device_types": {},
        "event_types": {
            "access_denied": malicious_count,
        },
    }

    output_file = tmp_path / "physical_event_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>access_denied</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_web_source_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.web_infrastructure_statistics = {
        "total_events": 1,
        "events_by_source": {
            "nginx": malicious_count,
        },
    }

    output_file = tmp_path / "web_source_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>nginx</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_network_total_events(tmp_path):
    malicious_total = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.network_statistics = {
        "total_network_events": malicious_total,
        "protocols": {},
        "dns_queries": [],
        "http_requests": 0,
    }

    output_file = tmp_path / "network_total_events_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "Total network events:" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_total not in html_content

def test_html_report_escapes_network_http_requests(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.network_statistics = {
        "total_network_events": 1,
        "protocols": {},
        "dns_queries": [],
        "http_requests": malicious_count,
    }

    output_file = tmp_path / "network_http_requests_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<strong>HTTP requests:</strong>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_linux_total_events(tmp_path):
    malicious_total = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_statistics = {
        "total_events": malicious_total,
        "actions": {},
        "statuses": {},
        "users": {},
        "source_ips": {},
    }

    output_file = tmp_path / "linux_total_events_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<strong>Total Linux events:</strong>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_total not in html_content

def test_html_report_escapes_linux_total_executions(tmp_path):
    malicious_total = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": malicious_total,
        "suspicious_executions": 0,
        "unique_executables": 0,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_total_executions_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<strong>Total executions analyzed:</strong>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_total not in html_content

def test_html_report_escapes_linux_unique_executables(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 1,
        "suspicious_executions": 0,
        "unique_executables": malicious_count,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "linux_unique_executables_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<strong>Unique executables:</strong>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_events_parsed(tmp_path):
    malicious_events_parsed = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "events_parsed": malicious_events_parsed,
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_events_parsed_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<h3>Events Parsed</h3>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_events_parsed not in html_content

def test_html_report_escapes_physical_total_findings(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "events_parsed": 1,
        "total_findings": malicious_count,
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_total_findings_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<h3>Total Findings</h3>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_policy_findings(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "events_parsed": 1,
        "total_findings": 1,
        "policy_findings": malicious_count,
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_policy_findings_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<h3>Policy Findings</h3>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_correlation_findings(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "events_parsed": 1,
        "total_findings": 1,
        "policy_findings": 0,
        "correlation_findings": malicious_count,
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_correlation_findings_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<h3>Correlation Findings</h3>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_detector_findings(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "events_parsed": 1,
        "total_findings": 1,
        "policy_findings": 0,
        "correlation_findings": 0,
        "detector_findings": malicious_count,
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_detector_findings_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<h3>Detector Findings</h3>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_critical_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": malicious_count,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_critical_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>Critical</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_high_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": 0,
            "high": malicious_count,
            "medium": 0,
            "low": 0,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_high_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>High</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_medium_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": malicious_count,
            "low": 0,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_medium_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>Medium</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_physical_low_count(tmp_path):
    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": malicious_count,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "physical_low_count_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<td>Low</td>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_count not in html_content

def test_html_report_escapes_web_total_events(tmp_path):
    malicious_total = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.web_infrastructure_statistics = {
        "total_events": malicious_total,
        "events_by_source": {},
    }

    output_file = tmp_path / "web_total_events_security_test.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert "<strong>Total normalized web events:</strong>" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
    assert malicious_total not in html_content

def test_html_report_linux_executable_row_structure(tmp_path):
    import re

    report = create_report()

    report.linux_execution_statistics = {
        "top_executables": [
            ("bash", 3),
        ],
    }

    output_file = tmp_path / "linux_executable_row_structure.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert re.search(
        r"<tr>\s*<td>bash</td>\s*<td>3</td>\s*</tr>",
        html_content,
    )

def test_html_report_preserves_suspicious_executions(tmp_path):
    import re

    malicious_count = "<img src=x onerror=alert(1)>"

    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": 10,
        "suspicious_executions": malicious_count,
        "unique_executables": 3,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
    }

    output_file = tmp_path / "suspicious_executions_regression.html"

    generate_html_report(report, str(output_file))

    html_content = output_file.read_text(encoding="utf-8")

    assert re.search(
        r"<strong>Suspicious executions:</strong>\s*"
        r"&lt;img src=x onerror=alert\(1\)&gt;",
        html_content,
    )

    assert malicious_count not in html_content

def test_generate_html_report_redacts_password_in_recommendation(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Login",
        severity="high",
        description="Suspicious authentication activity detected.",
        source="authentication_detector",
        ip="192.168.1.100",
        recommendation="Investigate login with password=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_test.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content
    assert "Suspicious Login" in content

    assert finding.recommendation == (
        "Investigate login with password=Secret123"
    )

def test_generate_html_report_redacts_password_in_finding_title(tmp_path):
    finding = ThreatFinding(
        title="Suspicious login password=Secret123",
        severity="high",
        description="Suspicious authentication activity.",
        source="authentication_detector",
        ip="192.168.1.100",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_title_test.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content

    assert finding.title == "Suspicious login password=Secret123"

def test_generate_html_report_redacts_password_in_report_title(tmp_path):
    report = ThreatReport(
        title="Security Report password=Secret123",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
    )

    output_file = tmp_path / "redaction_report_title.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Security Report" in content

    assert report.title == "Security Report password=Secret123"

def test_generate_html_report_redacts_password_in_timeline(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[
            {
                "time": "12:00:00",
                "event": "Failed login password=Secret123",
                "severity": "high",
                "ip": "192.168.1.100",
                "source": "authentication",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content
    assert "Failed login" in content

    assert report.timeline[0]["event"] == (
        "Failed login password=Secret123"
    )

def test_generate_html_report_redacts_password_in_hostname(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Host",
        severity="high",
        description="Suspicious network activity detected.",
        source="network_detector",
        ip="192.168.1.100",
        hostname="server password=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_hostname.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content
    assert "Suspicious Host" in content

    assert finding.hostname == "server password=Secret123"

def test_generate_html_report_redacts_api_key_in_ioc_source(tmp_path):
    finding = ThreatFinding(
        title="Malicious IP Detected",
        severity="high",
        description="Known malicious IP detected.",
        source="ioc_detector",
        ip="192.168.1.100",
        ioc_match=True,
        ioc_type="ip",
        ioc_value="192.168.1.100",
        ioc_source="Threat feed api_key=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_ioc_source.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Threat feed" in content
    assert "192.168.1.100" in content

    assert finding.ioc_source == "Threat feed api_key=Secret123"

def test_generate_html_report_redacts_password_in_executive_summary(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_execution_statistics={
            "top_executables": [
                ("bash password=Secret123", 3),
            ],
        },
    )

    output_file = tmp_path / "redaction_executive_summary.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    executive_summary = content.split("<pre>", 1)[1].split("</pre>", 1)[0]

    assert "password=[REDACTED]" in executive_summary
    assert "Secret123" not in executive_summary
    assert "Top executable: bash" in executive_summary

    assert report.linux_execution_statistics["top_executables"][0][0] == (
        "bash password=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_ioc_value(tmp_path):
    finding = ThreatFinding(
        title="Suspicious IOC Detected",
        severity="high",
        description="Suspicious indicator detected.",
        source="ioc_detector",
        ip="192.168.1.100",
        ioc_match=True,
        ioc_type="custom",
        ioc_value="indicator api_key=Secret123",
        ioc_source="Threat Intelligence Feed",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_ioc_value.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "indicator" in content
    assert "192.168.1.100" in content

    assert finding.ioc_value == "indicator api_key=Secret123"

def test_generate_html_report_redacts_password_in_linux_executables(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_execution_statistics={
            "top_executables": [
                ("bash password=Secret123", 3),
            ],
        },
    )

    output_file = tmp_path / "redaction_linux_executables.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "bash password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Linux Execution" in content

    assert report.linux_execution_statistics["top_executables"][0] == (
        "bash password=Secret123",
        3,
    )

def test_generate_html_report_redacts_password_in_linux_execution_users(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_execution_statistics={
            "top_users": [
                ("admin password=Secret123", 5),
            ],
        },
    )

    output_file = tmp_path / "redaction_linux_users.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "admin password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "admin" in content

    assert report.linux_execution_statistics["top_users"][0] == (
        "admin password=Secret123",
        5,
    )

def test_generate_html_report_redacts_password_in_linux_mitre_statistics(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_execution_statistics={
            "mitre_statistics": [
                ("T1059 password=Secret123", 3),
            ],
        },
    )

    output_file = tmp_path / "redaction_linux_mitre.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "T1059 password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "T1059" in content

    assert report.linux_execution_statistics["mitre_statistics"][0] == (
        "T1059 password=Secret123",
        3,
    )

def test_generate_html_report_redacts_api_key_in_timeline_source(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[
            {
                "time": "12:00:00",
                "event": "Suspicious network activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "source": "network_monitor api_key=Secret123",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_source.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "network_monitor" in content
    assert "192.168.1.100" in content

    assert report.timeline[0]["source"] == (
        "network_monitor api_key=Secret123"
    )

def test_generate_html_report_redacts_password_in_linux_actions(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_statistics={
            "actions": {
                "Failed login password=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_linux_actions.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "Failed login password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Failed login" in content

    assert report.linux_statistics["actions"] == {
        "Failed login password=Secret123": 5,
    }

def test_generate_html_report_redacts_password_in_linux_statuses(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_statistics={
            "statuses": {
                "Failed password=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_linux_statuses.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "Failed password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Failed" in content

    assert report.linux_statistics["statuses"] == {
        "Failed password=Secret123": 5,
    }

def test_generate_html_report_redacts_password_in_linux_users(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_statistics={
            "users": {
                "admin password=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_linux_users.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "admin password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "admin" in content

    assert report.linux_statistics["users"] == {
        "admin password=Secret123": 5,
    }

def test_generate_html_report_redacts_password_in_linux_source_ips(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-17 12:00:00",
        findings=[],
        timeline=[],
        linux_statistics={
            "source_ips": {
                "192.168.1.100 password=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_linux_source_ips.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "192.168.1.100 password=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content

    assert report.linux_statistics["source_ips"] == {
        "192.168.1.100 password=Secret123": 5,
    }

def test_generate_html_report_redacts_api_key_in_web_sources(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[],
        timeline=[],
        web_infrastructure_statistics={
            "events_by_source": {
                "nginx api_key=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_web_sources.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "nginx api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "nginx" in content

    assert report.web_infrastructure_statistics["events_by_source"] == {
        "nginx api_key=Secret123": 5,
    }

def test_generate_html_report_redacts_api_key_in_network_protocols(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[],
        timeline=[],
        network_statistics={
            "protocols": {
                "TCP api_key=Secret123": 5,
            },
        },
    )

    output_file = tmp_path / "redaction_network_protocols.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "TCP api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "TCP" in content

    assert report.network_statistics["protocols"] == {
        "TCP api_key=Secret123": 5,
    }

def test_generate_html_report_redacts_api_key_in_mitre_technique_name(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="MITRE Redaction Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application api_key=Secret123",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_mitre_technique_name.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "Exploit Public-Facing Application api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "T1190" in content
    assert "Initial Access" in content

    assert finding.technique_name == (
        "Exploit Public-Facing Application api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_mitre_technique(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="MITRE Technique Redaction Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190 api_key=Secret123",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_mitre_technique.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "T1190 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Exploit Public-Facing Application" in content
    assert "Initial Access" in content

    assert finding.technique == "T1190 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_mitre_tactic(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="MITRE Tactic Redaction Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access api_key=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_mitre_tactic.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "Initial Access api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "T1190" in content
    assert "Exploit Public-Facing Application" in content

    assert finding.tactic == "Initial Access api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_ioc_type(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="IOC Type Redaction Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        ioc_type="domain api_key=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_ioc_type.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "domain api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content

    assert finding.ioc_type == "domain api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_ioc_confidence(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="IOC Confidence Redaction Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        ioc_confidence="high api_key=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-18 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_ioc_confidence.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "high api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "192.168.1.100" in content

    assert finding.ioc_confidence == "high api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_physical_device_type(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "device_types": {
            "camera api_key=Secret123": 3,
        },
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_device_type.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "camera api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["device_types"] == {
        "camera api_key=Secret123": 3,
    }

def test_generate_html_report_redacts_api_key_in_physical_event_type(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "device_types": {},
        "event_types": {
            "access_denied api_key=Secret123": 5,
        },
    }

    output_file = tmp_path / "redaction_physical_event_type.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "access_denied api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["event_types"] == {
        "access_denied api_key=Secret123": 5,
    }

def test_generate_html_report_redacts_api_key_in_generated_at(tmp_path):
    report = create_report()

    report.generated_at = "2026-10-18 09:00:00 api_key=Secret123"

    output_file = tmp_path / "redaction_generated_at.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "2026-10-18 09:00:00 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.generated_at == "2026-10-18 09:00:00 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_timeline_time(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-19 08:00:00 api_key=Secret123",
                "event": "Suspicious network activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": "network_monitor",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_time.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "2026-10-19 08:00:00 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "Suspicious network activity" in content
    assert "192.168.1.100" in content

    assert (
        report.timeline[0]["time"]
        == "2026-10-19 08:00:00 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_timeline_severity(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-19 08:00:00",
                "event": "Suspicious network activity",
                "severity": "high api_key=Secret123",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": 80,
                "source": "network_monitor",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_severity.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "HIGH API_KEY=[REDACTED]" in content
    assert "SECRET123" not in content
    assert "192.168.1.100" in content

    assert report.timeline[0]["severity"] == "high api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_timeline_ip(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-19 08:00:00",
                "event": "Suspicious network activity",
                "severity": "high",
                "ip": "192.168.1.100 api_key=Secret123",
                "port": 443,
                "risk_score": 80,
                "source": "network_monitor",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_ip.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "192.168.1.100 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "Suspicious network activity" in content

    assert (
        report.timeline[0]["ip"]
        == "192.168.1.100 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_timeline_port(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-19 08:00:00",
                "event": "Suspicious network activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": "443 api_key=Secret123",
                "risk_score": 80,
                "source": "network_monitor",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_port.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "443 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content
    assert "Suspicious network activity" in content

    assert report.timeline[0]["port"] == "443 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_timeline_risk_score(tmp_path):
    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[],
        timeline=[
            {
                "time": "2026-10-19 08:00:00",
                "event": "Suspicious network activity",
                "severity": "high",
                "ip": "192.168.1.100",
                "port": 443,
                "risk_score": "80 api_key=Secret123",
                "source": "network_monitor",
            }
        ],
    )

    output_file = tmp_path / "redaction_timeline_risk_score.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "80 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content
    assert "Suspicious network activity" in content

    assert report.timeline[0]["risk_score"] == "80 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_finding_severity(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high api_key=Secret123",
        description="Severity Redaction Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_finding_severity.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "HIGH API_KEY=[REDACTED]" in content
    assert "SECRET123" not in content
    assert "192.168.1.100" in content
    assert "T1190" in content

    assert finding.severity == "high api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_finding_ip(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="IP Redaction Security Test",
        source="security_test",
        ip="192.168.1.100 api_key=Secret123",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_finding_ip.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "192.168.1.100 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "T1190" in content
    assert "Suspicious Activity" in content

    assert finding.ip == "192.168.1.100 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_finding_port(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="Port Redaction Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port="443 api_key=Secret123",
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_finding_port.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "443 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content
    assert "T1190" in content

    assert finding.port == "443 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_finding_risk_score(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="Risk Score Redaction Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score="80 api_key=Secret123",
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_finding_risk_score.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "80 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content
    assert "T1190" in content

    assert finding.risk_score == "80 api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_finding_ioc_match(tmp_path):
    finding = ThreatFinding(
        title="Suspicious Activity",
        severity="high",
        description="IOC Match Redaction Security Test",
        source="security_test",
        ip="192.168.1.100",
        hostname="test-server",
        port=443,
        risk_score=80,
        technique="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        ioc_match="True api_key=Secret123",
    )

    report = ThreatReport(
        title="Security Redaction Test",
        generated_at="2026-10-19 08:00:00",
        findings=[finding],
        timeline=[],
    )

    output_file = tmp_path / "redaction_finding_ioc_match.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "True api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content
    assert "T1190" in content

    assert finding.ioc_match == "True api_key=Secret123"

def test_generate_html_report_redacts_api_key_in_physical_device_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "device_types": {
            "camera": "3 api_key=Secret123",
        },
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_device_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "3 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "camera" in content

    assert report.physical_statistics["device_types"] == {
        "camera": "3 api_key=Secret123",
    }

def test_generate_html_report_redacts_api_key_in_physical_event_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "device_types": {},
        "event_types": {
            "access_denied": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_physical_event_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "access_denied" in content

    assert report.physical_statistics["event_types"] == {
        "access_denied": "5 api_key=Secret123",
    }

def test_generate_html_report_redacts_api_key_in_physical_events_parsed(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "events_parsed": "12 api_key=Secret123",
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_events_parsed.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "12 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["events_parsed"] == (
    "12 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_total_findings(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "total_findings": "7 api_key=Secret123",
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_total_findings.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "7 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["total_findings"] == (
        "7 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_policy_findings(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "policy_findings": "4 api_key=Secret123",
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_policy_findings.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "4 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["policy_findings"] == (
        "4 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_correlation_findings(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "correlation_findings": "6 api_key=Secret123",
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_correlation_findings.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "6 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["correlation_findings"] == (
        "6 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_detector_findings(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "detector_findings": "8 api_key=Secret123",
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_detector_findings.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "8 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["detector_findings"] == (
        "8 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_critical_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": "2 api_key=Secret123",
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_critical_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "2 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["severity_counts"]["critical"] == (
        "2 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_high_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "critical": 0,
            "high": "3 api_key=Secret123",
            "medium": 0,
            "low": 0,
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_high_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "3 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["severity_counts"]["high"] == (
        "3 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_medium_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "medium": "4 api_key=Secret123",
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_medium_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "4 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["severity_counts"]["medium"] == (
        "4 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_physical_low_count(tmp_path):
    report = create_report()

    report.physical_statistics = {
        "severity_counts": {
            "low": "2 api_key=Secret123",
        },
        "device_types": {},
        "event_types": {},
    }

    output_file = tmp_path / "redaction_physical_low_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "2 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.physical_statistics["severity_counts"]["low"] == (
        "2 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_web_source_count(tmp_path):
    report = create_report()

    report.web_infrastructure_statistics = {
        "total_events": 7,
        "events_by_source": {
            "nginx": "7 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_web_source_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "7 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.web_infrastructure_statistics["events_by_source"]["nginx"] == (
        "7 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_protocol_count(tmp_path):
    report = create_report()

    report.network_statistics = {
        "total_network_events": 5,
        "http_requests": 2,
        "protocols": {
            "TCP": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_protocol_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.network_statistics["protocols"]["TCP"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_linux_action_count(tmp_path):
    report = create_report()

    report.linux_statistics = {
        "total_events": 5,
        "actions": {
            "sudo": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_linux_action_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.linux_statistics["actions"]["sudo"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_linux_status_count(tmp_path):
    report = create_report()

    report.linux_statistics = {
        "total_events": 5,
        "statuses": {
            "failed": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_linux_status_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.linux_statistics["statuses"]["failed"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_linux_user_count(tmp_path):
    report = create_report()

    report.linux_statistics = {
        "total_events": 5,
        "users": {
            "root": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_linux_user_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert report.linux_statistics["users"]["root"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_linux_source_ip_count(tmp_path):
    report = create_report()

    report.linux_statistics = {
        "total_events": 5,
        "source_ips": {
            "192.168.1.100": "5 api_key=Secret123",
        },
    }

    output_file = tmp_path / "redaction_linux_source_ip_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "192.168.1.100" in content

    assert report.linux_statistics["source_ips"]["192.168.1.100"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_top_executable_count(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "top_executables": [
            ("/usr/bin/bash", "3 api_key=Secret123"),
        ],
    }

    output_file = tmp_path / "redaction_top_executable_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "3 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "/usr/bin/bash" in content

    assert report.linux_execution_statistics["top_executables"][0][1] == (
        "3 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_top_user_count(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "top_users": [
            ("root", "4 api_key=Secret123"),
        ],
    }

    output_file = tmp_path / "redaction_top_user_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "4 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "root" in content

    assert report.linux_execution_statistics["top_users"][0][1] == (
        "4 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_mitre_count(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "mitre_statistics": [
            ("T1059.004", "7 api_key=Secret123"),
        ],
    }

    output_file = tmp_path / "redaction_mitre_count.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "7 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "T1059.004" in content

    assert report.linux_execution_statistics["mitre_statistics"][0][1] == (
        "7 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_total_network_events(tmp_path):
    report = create_report()

    report.network_statistics = {
        "total_network_events": "8 api_key=Secret123",
        "http_requests": 3,
        "dns_queries": [],
        "protocols": {},
    }

    output_file = tmp_path / "redaction_total_network_events.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "8 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "Total network events:" in content

    assert report.network_statistics["total_network_events"] == (
        "8 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_http_requests(tmp_path):
    report = create_report()

    report.network_statistics = {
        "total_network_events": 8,
        "http_requests": "3 api_key=Secret123",
        "dns_queries": [],
        "protocols": {},
    }

    output_file = tmp_path / "redaction_http_requests.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "3 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "HTTP requests:" in content

    assert report.network_statistics["http_requests"] == (
        "3 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_linux_total_events(tmp_path):
    report = create_report()

    report.linux_statistics = {
        "total_events": "12 api_key=Secret123",
    }

    output_file = tmp_path / "redaction_linux_total_events.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "12 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "Total Linux events:" in content

    assert report.linux_statistics["total_events"] == (
        "12 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_total_executions(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "total_executions": "15 api_key=Secret123",
    }

    output_file = tmp_path / "redaction_total_executions.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "15 api_key=[REDACTED]" in content
    assert "Secret123" not in content

    assert "Total executions analyzed:" in content

    assert report.linux_execution_statistics["total_executions"] == (
        "15 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_suspicious_executions(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "suspicious_executions": "5 api_key=Secret123",
    }

    output_file = tmp_path / "redaction_suspicious_executions.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "5 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Suspicious executions:" in content

    assert report.linux_execution_statistics["suspicious_executions"] == (
        "5 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_unique_executables(tmp_path):
    report = create_report()

    report.linux_execution_statistics = {
        "unique_executables": "6 api_key=Secret123",
    }

    output_file = tmp_path / "redaction_unique_executables.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "6 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Unique executables:" in content

    assert report.linux_execution_statistics["unique_executables"] == (
        "6 api_key=Secret123"
    )

def test_generate_html_report_redacts_api_key_in_web_total_events(tmp_path):
    report = create_report()

    report.web_infrastructure_statistics = {
        "total_events": "20 api_key=Secret123",
        "events_by_source": {},
    }

    output_file = tmp_path / "redaction_web_total_events.html"

    generate_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "20 api_key=[REDACTED]" in content
    assert "Secret123" not in content
    assert "Total normalized web events:" in content

    assert report.web_infrastructure_statistics["total_events"] == (
        "20 api_key=Secret123"
    )
