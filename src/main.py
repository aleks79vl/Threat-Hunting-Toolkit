from datetime import datetime
from pathlib import Path

from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.windows_event_parser import parse_windows_events
from src.parsers.firewall_parser import parse_firewall_log
from src.parsers.web_log_parser import parse_web_log
from src.parsers.pcap_exporter import export_pcap_to_csv
from src.parsers.wireshark_csv_parser import parse_wireshark_csv
from src.parsers.linux_auth_parser import parse_auth_log
from src.parsers.linux_syslog_parser import parse_syslog

from src.detection.unknown_ip_detector import detect_unknown_ips
from src.detection.critical_port_detector import detect_critical_ports
from src.detection.windows_event_detector import detect_windows_events
from src.detection.firewall_detector import detect_firewall_events
from src.detection.web_attack_detector import detect_web_attacks

from src.detection.network_unknown_ip_detector import (detect_unknown_network_ips,)
from src.detection.network_critical_port_detector import (detect_network_critical_ports,)
from src.detection.network_ioc_detector import detect_network_iocs
from src.detection.network_web_attack_detector import (detect_network_web_attacks,)
from src.detection.dns_activity_detector import (detect_suspicious_dns_activity,)
from src.detection.packet_anomaly_detector import detect_packet_anomalies
from src.detection.mitm_detector import detect_arp_spoofing

from src.detection.linux_ssh_failed_login_detector import (detect_ssh_failed_logins,)
from src.detection.linux_ssh_bruteforce_detector import (detect_ssh_bruteforce,)
from src.detection.linux_successful_login_after_failures_detector import (
    detect_successful_login_after_failures,)
from src.detection.linux_telnet_detector import detect_telnet_activity
from src.detection.linux_sudo_abuse_detector import detect_sudo_abuse
from src.detection.linux_user_privilege_detector import (
    detect_linux_user_privilege_activity,)
from src.detection.linux_cron_activity_detector import (detect_suspicious_cron_activity,)
from src.detection.linux_service_manipulation_detector import (
    detect_linux_service_manipulation,)

from src.correlation.threat_correlation import correlate_threats
from src.correlation.network_correlation import correlate_network_findings
from src.correlation.risk_scoring import calculate_risk_score

from src.intelligence.ioc_matcher import enrich_finding_with_ioc
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score

from src.models.threat_report import ThreatReport

from src.reporting.json_report_generator import generate_json_report
from src.reporting.html_report_generator import generate_html_report
from src.reporting.timeline_generator import generate_timeline
from src.reporting.network_statistics import generate_network_statistics
from src.reporting.linux_statistics import generate_linux_statistics


def main():
    nmap_file = "data/raw/network/nmap_scan.xml"
    windows_events_file = "data/raw/windows/security_events.csv"
    firewall_file = "data/raw/firewall/firewall.log"
    web_log_file = "data/raw/web/apache_access.log"

    pcap_file = "data/raw/pcap/sample.pcap"
    pcap_csv_file = "data/processed/pcap/sample.csv"

    linux_auth_file = "data/raw/linux/auth.log"
    linux_syslog_file = "data/raw/linux/syslog"

    whitelist_file = "config/whitelist.json"
    critical_ports_file = "config/critical_ports.json"
    risk_scores_file = "config/risk_scores.json"

    json_output_file = "reports/threat_report.json"
    html_output_file = "reports/threat_report.html"

    # Traditional log sources

    nmap_events = parse_nmap_xml(nmap_file)
    unknown_events = detect_unknown_ips(nmap_events, whitelist_file)
    critical_events = detect_critical_ports(nmap_events,critical_ports_file,)
    nmap_findings = correlate_threats(unknown_events,critical_events,)

    windows_events = parse_windows_events(windows_events_file)
    windows_findings = detect_windows_events(windows_events)

    firewall_events = parse_firewall_log(firewall_file)
    firewall_findings = detect_firewall_events(firewall_events)

    web_events = parse_web_log(web_log_file)
    web_findings = detect_web_attacks(web_events)

    # PCAP / Wireshark pipeline

    network_events = []
    network_findings = []

    if Path(pcap_file).exists():
        export_pcap_to_csv(pcap_file,pcap_csv_file,)

        network_events = parse_wireshark_csv(pcap_csv_file)

    # Network Detection Layer

    if network_events:
        network_findings.extend(
            detect_unknown_network_ips(
                network_events,
                whitelist_file,
            )
        )

        network_findings.extend(
            detect_network_critical_ports(
                network_events,
                critical_ports_file,
            )
        )

        network_findings.extend(detect_network_iocs(network_events))
        network_findings.extend(detect_network_web_attacks(network_events))
        network_findings.extend(detect_suspicious_dns_activity(network_events))
        network_findings.extend(detect_packet_anomalies(network_events))
        network_findings.extend(detect_arp_spoofing(network_events))
        correlated_network_findings = correlate_network_findings(network_findings)
        network_findings.extend(correlated_network_findings)

    # Linux Log Pipeline

    linux_auth_events = []
    linux_syslog_events = []

    if Path(linux_auth_file).exists():
        linux_auth_events = parse_auth_log(linux_auth_file)

    if Path(linux_syslog_file).exists():
        linux_syslog_events = parse_syslog(linux_syslog_file)

    linux_events = linux_auth_events + linux_syslog_events
    linux_findings = []

    if linux_events:
        linux_findings.extend(detect_ssh_failed_logins(linux_events))
        linux_findings.extend(detect_ssh_bruteforce(linux_events))
        linux_findings.extend(detect_successful_login_after_failures(linux_events))
        linux_findings.extend(detect_telnet_activity(linux_events))
        linux_findings.extend(detect_sudo_abuse(linux_events))
        linux_findings.extend(detect_linux_user_privilege_activity(linux_events))
        linux_findings.extend(detect_suspicious_cron_activity(linux_events))
        linux_findings.extend(detect_linux_service_manipulation(linux_events))

    # Unified findings pipeline

    all_findings = (nmap_findings+ windows_findings+ firewall_findings
        + web_findings+ network_findings+ linux_findings)

    # Risk scoring

    scored_findings = [
        calculate_risk_score(
            finding,
            risk_scores_file,
        )
        for finding in all_findings
    ]

    # IOC Intelligence enrichment

    enriched_findings = []

    for finding in scored_findings:
        finding = enrich_finding_with_ioc(finding)
        finding = apply_ioc_risk_score(finding)
        enriched_findings.append(finding)

    # Reporting data

    timeline = generate_timeline(enriched_findings)
    network_statistics = generate_network_statistics(network_events)
    linux_statistics = generate_linux_statistics(linux_events)

    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=enriched_findings,
        timeline=timeline,
    )

    report.network_statistics = network_statistics
    report.linux_statistics = linux_statistics

    # Report generation

    generate_json_report(report,json_output_file,)
    generate_html_report(report,html_output_file,)

    # Console summary

    print("Threat Hunting Report generated successfully.")
    print(f"JSON output file: {json_output_file}")
    print(f"HTML output file: {html_output_file}")
    print(f"Total findings: {report.total_findings()}")
    print("Critical findings: "f"{report.count_by_severity('critical')}")
    print(f"Network events parsed: {len(network_events)}")
    print(f"Network findings: {len(network_findings)}")
    print(f"Linux events parsed: {len(linux_events)}")
    print(f"Linux findings: {len(linux_findings)}")


if __name__ == "__main__":
    main()