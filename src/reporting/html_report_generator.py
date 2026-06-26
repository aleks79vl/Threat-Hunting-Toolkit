from pathlib import Path

from src.models.threat_report import ThreatReport
from src.reporting.executive_summary import generate_executive_summary


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

    findings_rows = ""

    for finding in report.findings:
        findings_rows += f"""
        <tr>
            <td>{finding.title}</td>
            <td>{finding.severity.upper()}</td>
            <td>{finding.ip}</td>
            <td>{finding.hostname}</td>
            <td>{finding.port}</td>
            <td>{finding.risk_score}</td>
            <td>{finding.recommendation}</td>
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
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)