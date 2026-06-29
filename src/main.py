from datetime import datetime

from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.windows_event_parser import parse_windows_events
from src.parsers.firewall_parser import parse_firewall_log

from src.detection.unknown_ip_detector import detect_unknown_ips
from src.detection.critical_port_detector import detect_critical_ports
from src.detection.windows_event_detector import detect_windows_events
from src.detection.firewall_detector import detect_firewall_events

from src.correlation.threat_correlation import correlate_threats
from src.correlation.risk_scoring import calculate_risk_score

from src.models.threat_report import ThreatReport

from src.reporting.json_report_generator import generate_json_report
from src.reporting.html_report_generator import generate_html_report
from src.reporting.timeline_generator import generate_timeline


def main():
    nmap_file = "data/raw/network/nmap_scan.xml"
    windows_events_file = "data/raw/windows/security_events.csv"
    firewall_file = "data/raw/firewall/firewall.log"

    whitelist_file = "config/whitelist.json"
    critical_ports_file = "config/critical_ports.json"
    risk_scores_file = "config/risk_scores.json"

    json_output_file = "reports/threat_report.json"
    html_output_file = "reports/threat_report.html"

    nmap_events = parse_nmap_xml(nmap_file)

    unknown_events = detect_unknown_ips(
        nmap_events,
        whitelist_file
    )

    critical_events = detect_critical_ports(
        nmap_events,
        critical_ports_file
    )

    nmap_findings = correlate_threats(
        unknown_events,
        critical_events
    )

    windows_events = parse_windows_events(
        windows_events_file
    )

    windows_findings = detect_windows_events(
        windows_events
    )

    firewall_events = parse_firewall_log(
        firewall_file
    )

    firewall_findings = detect_firewall_events(
        firewall_events
    )

    all_findings = (
        nmap_findings
        + windows_findings
        + firewall_findings
    )

    scored_findings = [
        calculate_risk_score(
            finding,
            risk_scores_file
        )
        for finding in all_findings
    ]

    timeline = generate_timeline(scored_findings)

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=scored_findings,
        timeline=timeline
    )

    generate_json_report(
        report,
        json_output_file
    )

    generate_html_report(
        report,
        html_output_file
    )

    print("Threat Hunting Report generated successfully.")
    print(f"JSON output file: {json_output_file}")
    print(f"HTML output file: {html_output_file}")
    print(f"Total findings: {report.total_findings()}")
    print(f"Critical findings: {report.count_by_severity('critical')}")


if __name__ == "__main__":
    main()
