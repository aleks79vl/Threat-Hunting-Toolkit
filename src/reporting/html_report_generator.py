from pathlib import Path

from src.models.threat_report import ThreatReport
from src.reporting.executive_summary import generate_executive_summary
from src.reporting.mitre_statistics import generate_mitre_statistics


def generate_html_report(
    report: ThreatReport,
    output_path: str = "reports/threat_report.html"
) -> None:
    output_file = Path(output_path)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    executive_summary = generate_executive_summary(report)
    summary = report.summary()
    mitre_stats = generate_mitre_statistics(report.findings)

    network_statistics = getattr(
        report,
        "network_statistics",
        {
            "total_network_events": 0,
            "protocols": {},
            "dns_queries": [],
            "http_requests": 0,
        }
    )

    protocol_rows = ""

    for protocol, count in network_statistics["protocols"].items():
        protocol_rows += f"<li>{protocol}: {count}</li>"

    findings_rows = ""

    for finding in report.findings:
        findings_rows += f"""
        <tr>
            <td>
                <b>{finding.title}</b><br>

                <small>
                    <b>MITRE ATT&CK</b><br>
                    <b>Technique:</b> {getattr(finding, "technique", "Unknown")}<br>
                    <b>Name:</b> {getattr(finding, "technique_name", "Unknown")}<br>
                    <b>Tactic:</b> {getattr(finding, "tactic", "Unknown")}<br><br>

                    <b>IOC Intelligence</b><br>
                    <b>IOC Match:</b> {getattr(finding, "ioc_match", False)}<br>
                    <b>IOC Type:</b> {getattr(finding, "ioc_type", "")}<br>
                    <b>IOC Value:</b> {getattr(finding, "ioc_value", "")}<br>
                    <b>IOC Confidence:</b> {getattr(finding, "ioc_confidence", "")}<br>
                    <b>IOC Source:</b> {getattr(finding, "ioc_source", "")}
                </small>
            </td>
            <td>{finding.severity.upper()}</td>
            <td>{finding.ip}</td>
            <td>{finding.hostname}</td>
            <td>{finding.port}</td>
            <td>{finding.risk_score}</td>
            <td>{finding.recommendation}</td>
        </tr>
        """

    timeline_rows = ""

    for item in report.timeline:
        timeline_rows += f"""
        <tr>
            <td>{item.get("time", "")}</td>
            <td>{item.get("event", "")}</td>
            <td>{item.get("severity", "").upper()}</td>
            <td>{item.get("ip", "")}</td>
            <td>{item.get("port", "")}</td>
            <td>{item.get("risk_score", "")}</td>
            <td>{item.get("source", "")}</td>
        </tr>
        """

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
</head>
<body>
    <h1>{report.title}</h1>

    <p><strong>Generated at:</strong> {report.generated_at}</p>

    <h2>Executive Summary</h2>
    <pre>{executive_summary}</pre>

    <h2>MITRE ATT&CK Statistics</h2>
    <ul>
        <li><strong>Unique tactics:</strong> {len(mitre_stats["tactics"])}</li>
        <li><strong>Unique techniques:</strong> {len(mitre_stats["techniques"])}</li>
    </ul>

    <h2>Network Traffic Summary</h2>
    <ul>
        <li><strong>Total network events:</strong> {network_statistics["total_network_events"]}</li>
        <li><strong>HTTP requests:</strong> {network_statistics["http_requests"]}</li>
        <li><strong>DNS queries:</strong> {len(network_statistics["dns_queries"])}</li>
    </ul>

    <h3>Protocols Observed</h3>
    <ul>
        {protocol_rows}
    </ul>

    <h2>Threat Statistics</h2>
    <ul>
        <li>Total findings: {summary["total_findings"]}</li>
        <li>Critical: {summary["critical"]}</li>
        <li>High: {summary["high"]}</li>
        <li>Medium: {summary["medium"]}</li>
        <li>Low: {summary["low"]}</li>
    </ul>

    <h2>Detected Threats</h2>
    <table border="1" cellpadding="8">
        <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>IP</th>
            <th>Hostname</th>
            <th>Port</th>
            <th>Risk Score</th>
            <th>Recommendation</th>
        </tr>
        {findings_rows}
    </table>

    <h2>Threat Timeline</h2>
    <table border="1" cellpadding="8">
        <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Severity</th>
            <th>IP</th>
            <th>Port</th>
            <th>Risk Score</th>
            <th>Source</th>
        </tr>
        {timeline_rows}
    </table>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)