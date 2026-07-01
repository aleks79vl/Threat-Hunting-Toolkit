from src.models.threat_report import ThreatReport
from src.reporting.mitre_statistics import generate_mitre_statistics


def generate_executive_summary(report: ThreatReport) -> str:
    summary = report.summary()

    highest_risk_score = 0

    if report.findings:
        highest_risk_score = max(
            finding.risk_score
            for finding in report.findings
        )
    mitre_stats = generate_mitre_statistics(report.findings)

    tactics = mitre_stats["tactics"]
    techniques = mitre_stats["techniques"]

    most_common_tactic = (
        max(tactics, key=tactics.get)
        if tactics
        else "Unknown"
    )

    most_common_technique = (
        max(techniques, key=techniques.get)
        if techniques
        else "Unknown"
    )
    

    lines = [
        "Threat Hunting Summary",
        "",
        "Analysis completed successfully.",
        "",
        f"Total findings: {summary['total_findings']}",
        f"Critical findings: {summary['critical']}",
        f"High findings: {summary['high']}",
        f"Medium findings: {summary['medium']}",
        f"Low findings: {summary['low']}",
        "",
        f"Highest risk score: {highest_risk_score}",
        "",
    ]

    if summary["critical"] > 0:
        lines.append("Immediate investigation is recommended due to critical findings.")

    elif summary["high"] > 0:
        lines.append("Priority review is recommended due to high severity findings.")

    else:
        lines.append("No critical or high severity findings were detected.")

        lines.extend(
            [
                "",
                "MITRE ATT&CK Summary",
                "",
                f"Most observed tactic: {most_common_tactic}",
                f"Most observed technique: {most_common_technique}",
                f"Unique tactics: {len(tactics)}",
                f"Unique techniques: {len(techniques)}",
            ]
        )

    return "\n".join(lines)

 