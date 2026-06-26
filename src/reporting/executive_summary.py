from src.models.threat_report import ThreatReport


def generate_executive_summary(report: ThreatReport) -> str:
    summary = report.summary()

    highest_risk_score = 0

    if report.findings:
        highest_risk_score = max(
            finding.risk_score
            for finding in report.findings
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

    return "\n".join(lines)