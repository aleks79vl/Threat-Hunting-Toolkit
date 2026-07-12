from src.models.threat_report import ThreatReport
from src.reporting.mitre_statistics import generate_mitre_statistics


def generate_executive_summary(report: ThreatReport) -> str:
    summary = report.summary()

    highest_risk_score = 0

    if report.findings:
        highest_risk_score = max(finding.risk_score for finding in report.findings)

    mitre_stats = generate_mitre_statistics(report.findings)

    tactics = mitre_stats["tactics"]
    techniques = mitre_stats["techniques"]

    most_common_tactic = (max(tactics, key=tactics.get)
        if tactics
        else "Unknown")

    most_common_technique = (max(techniques, key=techniques.get)
        if techniques
        else "Unknown")

    linux_execution_statistics = {
        "total_executions": 0,
        "suspicious_executions": 0,
        "unique_executables": 0,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
        **getattr(report,
            "linux_execution_statistics",
            {},),}

    top_executables = linux_execution_statistics.get("top_executables",[],)

    top_users = linux_execution_statistics.get("top_users",[],)

    linux_mitre_statistics = linux_execution_statistics.get("mitre_statistics",[],)

    top_executable = (top_executables[0][0]
        if top_executables
        else "N/A")

    most_active_user = (top_users[0][0]
        if top_users
        else "N/A")

    top_linux_mitre_technique = (linux_mitre_statistics[0][0]
        if linux_mitre_statistics
        else "N/A")

    lines = ["Threat Hunting Summary","","Analysis completed successfully.","",
        f"Total findings: {summary['total_findings']}",
        f"Critical findings: {summary['critical']}",
        f"High findings: {summary['high']}",
        f"Medium findings: {summary['medium']}",
        f"Low findings: {summary['low']}","",
        f"Highest risk score: {highest_risk_score}",]

    if summary["critical"] > 0:
        lines.append("Immediate investigation is recommended "
            "due to critical findings.")

    elif summary["high"] > 0:lines.append("Priority review is recommended "
        "due to high severity findings.")

    else:
        lines.append("No critical or high severity findings were detected.")

    lines.extend(["","MITRE ATT&CK Summary","",
        f"Most observed tactic: {most_common_tactic}",
        f"Most observed technique: {most_common_technique}",
        f"Unique tactics: {len(tactics)}",
        f"Unique techniques: {len(techniques)}",])

    lines.extend(["","Advanced Linux Execution Summary","",
        ("Total executions: " f"{linux_execution_statistics['total_executions']}"),
        ("Suspicious executions: " f"{linux_execution_statistics['suspicious_executions']}"),
        ("Unique executables: " f"{linux_execution_statistics['unique_executables']}"),
        f"Top executable: {top_executable}",f"Most active user: {most_active_user}",
        ("Top MITRE technique: " f"{top_linux_mitre_technique}"),])

    return "\n".join(lines)
 