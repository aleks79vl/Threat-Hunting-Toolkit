from pathlib import Path

from html import escape

from src.models.threat_report import ThreatReport
from src.reporting.executive_summary import generate_executive_summary
from src.reporting.mitre_statistics import generate_mitre_statistics

def _generate_physical_security_section(report) -> str:
    """
    Generate the Physical Security section for the HTML report.

    The function uses getattr so older ThreatReport objects remain
    compatible when Physical Security data is unavailable.
    """

    statistics = getattr(report,"physical_statistics",{},) or {}
    risk_score = getattr(report,"physical_risk_score",0,)
    events_parsed = statistics.get("events_parsed",0,)
    detector_findings = statistics.get("detector_findings",0,)
    policy_findings = statistics.get("policy_findings",0,)
    correlation_findings = statistics.get("correlation_findings",0,)
    total_findings = statistics.get("total_findings",0,)
    severity_counts = statistics.get("severity_counts",{},) or {}
    device_types = statistics.get("device_types",{},) or {}
    event_types = statistics.get("event_types",{},) or {}
    critical_count = severity_counts.get("critical",0,)
    high_count = severity_counts.get("high",0,)
    medium_count = severity_counts.get("medium",0,)
    low_count = severity_counts.get("low",0,)

    if risk_score >= 90:
        risk_level = "Critical"
        risk_class = "critical"
    elif risk_score >= 70:
        risk_level = "High"
        risk_class = "high"
    elif risk_score >= 40:
        risk_level = "Medium"
        risk_class = "medium"
    else:
        risk_level = "Low"
        risk_class = "low"

    device_rows = "".join(
        (
            "<tr>"
            f"<td>{escape(str(device_type))}</td>"
            f"<td>{count}</td>"
            "</tr>"
        )
        for device_type, count in sorted(device_types.items()))

    if not device_rows:
        device_rows = (
            "<tr>"
            "<td colspan=\"2\">No device telemetry available</td>"
            "</tr>"
        )

    event_rows = "".join(
        ("<tr>"
            f"<td>{escape(str(event_type))}</td>"
            f"<td>{count}</td>"
            "</tr>")
        for event_type, count in sorted(event_types.items()))

    if not event_rows:
        event_rows = (
            "<tr>"
            "<td colspan=\"2\">No physical events available</td>"
            "</tr>"
        )

    return f"""
    <section class="report-section physical-security-section">
        <h2>Physical Security</h2>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>Physical Risk Score</h3>
                <div class="risk-score {risk_class}">
                    {risk_score}/100
                </div>
                <p>{risk_level} Risk</p>
            </div>

            <div class="summary-card">
                <h3>Events Parsed</h3>
                <div class="metric-value">{events_parsed}</div>
            </div>

            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="metric-value">{total_findings}</div>
            </div>

            <div class="summary-card">
                <h3>Policy Findings</h3>
                <div class="metric-value">{policy_findings}</div>
            </div>

            <div class="summary-card">
                <h3>Correlation Findings</h3>
                <div class="metric-value">
                    {correlation_findings}
                </div>
            </div>

            <div class="summary-card">
                <h3>Detector Findings</h3>
                <div class="metric-value">
                    {detector_findings}
                </div>
            </div>
        </div>

        <h3>Severity Distribution</h3>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Critical</td>
                    <td>{critical_count}</td>
                </tr>
                <tr>
                    <td>High</td>
                    <td>{high_count}</td>
                </tr>
                <tr>
                    <td>Medium</td>
                    <td>{medium_count}</td>
                </tr>
                <tr>
                    <td>Low</td>
                    <td>{low_count}</td>
                </tr>
            </tbody>
        </table>

        <h3>Physical Device Types</h3>

        <table>
            <thead>
                <tr>
                    <th>Device Type</th>
                    <th>Events</th>
                </tr>
            </thead>
            <tbody>
                {device_rows}
            </tbody>
        </table>

        <h3>Physical Event Types</h3>

        <table>
            <thead>
                <tr>
                    <th>Event Type</th>
                    <th>Events</th>
                </tr>
            </thead>
            <tbody>
                {event_rows}
            </tbody>
        </table>
    </section>
    """

def generate_html_report(
    report: ThreatReport,
    output_path: str = "reports/threat_report.html"
) -> None:
    output_file = Path(output_path)

    output_file.parent.mkdir(parents=True,exist_ok=True)

    executive_summary = generate_executive_summary(report)
    summary = report.summary()
    mitre_stats = generate_mitre_statistics(report.findings)
    physical_security_section = (_generate_physical_security_section(report))

    network_statistics = {
        "total_network_events": 0,
        "protocols": {},
        "dns_queries": [],
        "http_requests": 0,
        **getattr(report, "network_statistics", {}),
    }

    linux_statistics = {
        "total_events": 0,
        "actions": {},
        "statuses": {},
        "users": {},
        "source_ips": {},
        **getattr(report, "linux_statistics", {}),
    }

    linux_execution_statistics = {
        "total_executions": 0,
        "suspicious_executions": 0,
        "unique_executables": 0,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
         **getattr(report, "linux_execution_statistics", {}),
    }

    protocol_rows = ""

    for protocol, count in network_statistics["protocols"].items():
        protocol_rows += f"<li>{protocol}: {count}</li>"

    linux_action_rows = "".join(f"<tr><td>{action}</td><td>{count}</td></tr>"
        for action, count in linux_statistics.get("actions", {}).items())
    linux_status_rows = "".join(f"<tr><td>{status}</td><td>{count}</td></tr>"
        for status, count in linux_statistics.get("statuses", {}).items())
    linux_user_rows = "".join(f"<tr><td>{user}</td><td>{count}</td></tr>"
        for user, count in linux_statistics.get("users", {}).items())
    linux_source_ip_rows = "".join(f"<tr><td>{ip}</td><td>{count}</td></tr>"
        for ip, count in linux_statistics.get("source_ips", {}).items())

    findings_rows = ""

    for finding in report.findings:
        findings_rows += f"""
        <tr>
            <td>
                <b>{finding.title}</b><br><br>

                <small>
                    <b>MITRE ATT&CK:</b><br>
                    <b>Technique:</b> {getattr(finding, "technique", "Unknown")}<br>
                    <b>Name:</b> {getattr(finding, "technique_name", "Unknown")}<br>
                    <b>Tactic:</b> {getattr(finding, "tactic", "Unknown")}<br><br>

                    <b>IOC Intelligence:</b><br>
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

    linux_execution_rows = "".join(
        f"""
        <tr>
            <td>{executable}</td>
            <td>{count}</td>
        </tr>
        """
        for executable, count in linux_execution_statistics.get(
            "top_executables",
            [],
        )
    )

    linux_execution_user_rows = "".join(
        f"""
        <tr>
            <td>{user}</td>
            <td>{count}</td>
        </tr>
        """
        for user, count in linux_execution_statistics.get(
            "top_users",
            [],
        )
    )

    linux_execution_mitre_rows = "".join(
        f"""
        <tr>
            <td>{technique}</td>
            <td>{count}</td>
        </tr>
        """
        for technique, count in linux_execution_statistics.get(
            "mitre_statistics",
            [],
        )
    )

    if not linux_execution_rows:
        linux_execution_rows = """
        <tr>
            <td colspan="2">No executable data available</td>
        </tr>
        """

    if not linux_execution_user_rows:
        linux_execution_user_rows = """
        <tr>
            <td colspan="2">No user data available</td>
        </tr>
        """

    if not linux_execution_mitre_rows:
        linux_execution_mitre_rows = """
        <tr>
            <td colspan="2">No MITRE data available</td>
        </tr>
        """

    physical_security_section = _generate_physical_security_section(report)

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

    <h2>Linux Security Statistics</h2>
    <ul>
        <li><strong>Total Linux events:</strong> {linux_statistics.get("total_events", 0)}</li>
    </ul>

    <h3>Linux Actions</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>Action</th>
            <th>Count</th>
        </tr>
        {linux_action_rows}
    </table>

    <h3>Linux Statuses</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>Status</th>
            <th>Count</th>
        </tr>
        {linux_status_rows}
    </table>

    <h3>Linux Users</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>User</th>
            <th>Count</th>
        </tr>
        {linux_user_rows}
    </table>

    <h3>Linux Source IPs</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>Source IP</th>
            <th>Count</th>
        </tr>
        {linux_source_ip_rows}
    </table>

    <h2>Advanced Linux Execution Statistics</h2>
    <ul>
        <li>
            <strong>Total executions analyzed:</strong>
            {linux_execution_statistics.get("total_executions", 0)}
        </li>
        <li>
            <strong>Suspicious executions:</strong>
            {linux_execution_statistics.get("suspicious_executions", 0)}
        </li>
        <li>
            <strong>Unique executables:</strong>
            {linux_execution_statistics.get("unique_executables", 0)}
        </li>
    </ul>

    <h3>Top Executables</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>Executable</th>
            <th>Count</th>
        </tr>
        {linux_execution_rows}
    </table>

    <h3>Top Linux Users</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>User</th>
            <th>Count</th>
        </tr>
        {linux_execution_user_rows}
    </table>

    <h3>Advanced Linux MITRE Coverage</h3>
    <table border="1" cellpadding="8">
        <tr>
            <th>MITRE Technique</th>
            <th>Detections</th>
        </tr>
        {linux_execution_mitre_rows}
    </table>

    {physical_security_section}

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