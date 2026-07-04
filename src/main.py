from datetime import datetime
from pathlib import Path

from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.windows_event_parser import parse_windows_events
from src.parsers.firewall_parser import parse_firewall_log
from src.parsers.web_log_parser import parse_web_log

from src.detection.unknown_ip_detector import detect_unknown_ips
from src.detection.critical_port_detector import detect_critical_ports
from src.detection.windows_event_detector import detect_windows_events
from src.detection.firewall_detector import detect_firewall_events
from src.detection.web_attack_detector import detect_web_attacks

from src.correlation.threat_correlation import correlate_threats
from src.correlation.risk_scoring import calculate_risk_score

from src.intelligence.ioc_matcher import enrich_finding_with_ioc
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score

from src.models.threat_report import ThreatReport

from src.reporting.json_report_generator import generate_json_report
from src.reporting.html_report_generator import generate_html_report
from src.reporting.timeline_generator import generate_timeline

from src.parsers.pcap_exporter import export_pcap_to_csv
from src.parsers.wireshark_csv_parser import parse_wireshark_csv

from src.reporting.network_statistics import generate_network_statistics


def main():
    nmap_file = "data/raw/network/nmap_scan.xml"
    windows_events_file = "data/raw/windows/security_events.csv"
    firewall_file = "data/raw/firewall/firewall.log"
    web_log_file = "data/raw/web/apache_access.log"
    pcap_file = "data/raw/pcap/sample.pcap"
    pcap_csv_file = "data/processed/pcap/sample.csv"

    whitelist_file = "config/whitelist.json"
    critical_ports_file = "config/critical_ports.json"
    risk_scores_file = "config/risk_scores.json"

    json_output_file = "reports/threat_report.json"
    html_output_file = "reports/threat_report.html"

    nmap_events = parse_nmap_xml(nmap_file)

    unknown_events = detect_unknown_ips(nmap_events,whitelist_file)

    critical_events = detect_critical_ports(nmap_events,critical_ports_file)

    nmap_findings = correlate_threats(unknown_events,critical_events)

    windows_events = parse_windows_events(windows_events_file)

    windows_findings = detect_windows_events(windows_events)

    firewall_events = parse_firewall_log(firewall_file)

    firewall_findings = detect_firewall_events(firewall_events)

    web_events = parse_web_log(web_log_file)

    web_findings = detect_web_attacks(web_events)

    network_events = []

    if Path(pcap_file).exists():
        export_pcap_to_csv(pcap_file,pcap_csv_file)

        network_events = parse_wireshark_csv(pcap_csv_file)

    all_findings = (
        nmap_findings
        + windows_findings
        + firewall_findings
        + web_findings
    )

    scored_findings = [
        calculate_risk_score(finding,risk_scores_file)
        for finding in all_findings
    ]

    enriched_findings = []

    for finding in scored_findings:
        finding = enrich_finding_with_ioc(finding)
        finding = apply_ioc_risk_score(finding)
        enriched_findings.append(finding)

    timeline = generate_timeline(enriched_findings)

    network_statistics = generate_network_statistics(network_events)

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=enriched_findings,
        timeline=timeline
    )

    report.network_statistics = network_statistics

    generate_json_report(report, json_output_file)

    generate_html_report(report, html_output_file)

    print("Threat Hunting Report generated successfully.")
    print(f"JSON output file: {json_output_file}")
    print(f"HTML output file: {html_output_file}")
    print(f"Total findings: {report.total_findings()}")
    print(f"Critical findings: {report.count_by_severity('critical')}")
    print(f"Network events parsed: {len(network_events)}")


if __name__ == "__main__":
    main()