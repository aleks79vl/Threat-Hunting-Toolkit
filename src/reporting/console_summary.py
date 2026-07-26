from src.models.threat_report import ThreatReport


def print_console_summary(
    report: ThreatReport,
    *,
    json_output_file: str,
    html_output_file: str,
    network_event_count: int,
    network_finding_count: int,
    linux_event_count: int,
    linux_finding_count: int,
    physical_event_count: int,
    physical_finding_count: int,
    physical_policy_finding_count: int,
    physical_correlation_finding_count: int,
    physical_risk_score: int,
) -> None:
    print("Threat Hunting Report generated successfully.")
    print(f"JSON output file: {json_output_file}")
    print(f"HTML output file: {html_output_file}")
    print(f"Total findings: {report.total_findings()}")
    print(
        "Critical findings: "
        f"{report.count_by_severity('critical')}"
    )
    print(f"Network events parsed: {network_event_count}")
    print(f"Network findings: {network_finding_count}")
    print(f"Linux events parsed: {linux_event_count}")
    print(f"Linux findings: {linux_finding_count}")
    print(f"Physical events parsed: {physical_event_count}")
    print(f"Physical findings: {physical_finding_count}")
    print(
        "Physical policy findings: "
        f"{physical_policy_finding_count}"
    )
    print(
        "Physical correlation findings: "
        f"{physical_correlation_finding_count}"
    )
    print(f"Physical risk score: {physical_risk_score}")