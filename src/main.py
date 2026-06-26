from datetime import datetime

from src.parsers.nmap_parser import parse_nmap_xml
from src.detection.unknown_ip_detector import detect_unknown_ips
from src.detection.critical_port_detector import detect_critical_ports
from src.correlation.threat_correlation import correlate_threats
from src.models.threat_report import ThreatReport
from src.reporting.json_report_generator import generate_json_report


def main():
    nmap_file = "data/raw/network/nmap_scan.xml"
    whitelist_file = "config/whitelist.json"
    critical_ports_file = "config/critical_ports.json"
    output_file = "reports/threat_report.json"

    events = parse_nmap_xml(nmap_file)

    unknown_events = detect_unknown_ips(
        events,
        whitelist_file
    )

    critical_events = detect_critical_ports(
        events,
        critical_ports_file
    )

    findings = correlate_threats(
        unknown_events,
        critical_events
    )

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings
    )

    generate_json_report(
        report,
        output_file
    )

    print("Threat Hunting Report generated successfully.")
    print(f"Output file: {output_file}")
    print(f"Total findings: {report.total_findings()}")
    print(f"Critical findings: {report.count_by_severity('critical')}")


if __name__ == "__main__":
    main()