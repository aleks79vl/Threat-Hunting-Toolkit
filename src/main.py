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

from src.detection.nmap.unknown_ip_detector import detect_unknown_ips
from src.detection.nmap.critical_port_detector import detect_critical_ports
from src.detection.windows.windows_event_detector import detect_windows_events
from src.detection.firewall.firewall_detector import detect_firewall_events
from src.detection.web.web_attack_detector import detect_web_attacks

from src.detection.nmap.network_unknown_ip_detector import (detect_unknown_network_ips,)
from src.detection.nmap.network_critical_port_detector import (detect_network_critical_ports,)
from src.detection.network.network_ioc_detector import detect_network_iocs
from src.detection.network.network_web_attack_detector import (detect_network_web_attacks,)
from src.detection.network.dns_activity_detector import (detect_suspicious_dns_activity,)
from src.detection.network.packet_anomaly_detector import detect_packet_anomalies
from src.detection.network.mitm_detector import detect_arp_spoofing

from src.detection.linux.ssh_failed_login_detector import (detect_ssh_failed_logins,)
from src.detection.linux.ssh_bruteforce_detector import (detect_ssh_bruteforce,)
from src.detection.linux.successful_login_after_failures_detector import (
    detect_successful_login_after_failures,)
from src.detection.linux.telnet_detector import detect_telnet_activity
from src.detection.linux.sudo_abuse_detector import detect_sudo_abuse
from src.detection.linux.user_privilege_detector import (
    detect_linux_user_privilege_activity,)
from src.detection.linux.cron_activity_detector import (detect_suspicious_cron_activity,)
from src.detection.linux.service_manipulation_detector import (
    detect_linux_service_manipulation,)

from src.detection.linux.detection_context import LinuxDetectionContext
from src.models.linux_process_execution import LinuxProcessExecution

from src.detection.linux.suspicious_process_detector import (
    detect_suspicious_linux_processes,)
from src.detection.linux.reverse_shell_detector import (detect_linux_reverse_shells,)
from src.detection.linux.advanced_telnet_detector import (detect_advanced_telnet_activity,)
from src.detection.linux.ssh_persistence_detector import (detect_linux_ssh_persistence,)
from src.detection.linux.audit_tampering_detector import (detect_linux_audit_tampering,)
from src.detection.linux.log_clearing_detector import (detect_linux_log_clearing,)
from src.detection.linux.file_permission_detector import (detect_suspicious_file_permissions,)
from src.detection.linux.systemd_persistence_detector import (detect_linux_systemd_persistence,)
from src.detection.linux.cron_persistence_detector import (detect_linux_cron_persistence,)

from src.detection.linux.advanced_risk_scoring import (calculate_advanced_linux_risk_score,)
from src.detection.linux.mitre_mapping import (get_linux_mitre_techniques,)

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

from src.reporting.linux_execution_statistics import (generate_linux_execution_statistics,)


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

        # Advanced Linux Execution Analysis Layer

        linux_executions = []

        for event in linux_events:
            context = LinuxDetectionContext.from_event(event)
            execution = LinuxProcessExecution.from_context(context)

            if execution.searchable_text():
                linux_executions.append(execution)

        advanced_linux_findings = []

        for execution in linux_executions:
            execution_findings = []

            execution_findings.extend(detect_suspicious_linux_processes([execution]))
            execution_findings.extend(detect_linux_reverse_shells([execution]))
            execution_findings.extend(detect_advanced_telnet_activity([execution]))
            execution_findings.extend(detect_linux_ssh_persistence([execution]))
            execution_findings.extend(detect_linux_audit_tampering([execution]))
            execution_findings.extend(detect_linux_log_clearing([execution]))
            execution_findings.extend(detect_suspicious_file_permissions([execution]))
            execution_findings.extend(detect_linux_systemd_persistence([execution]))
            execution_findings.extend(detect_linux_cron_persistence([execution]))

            for finding in execution_findings:
                finding.risk_score = calculate_advanced_linux_risk_score(finding,execution,)

                techniques = get_linux_mitre_techniques(finding)

                if techniques:
                    primary_technique = techniques[0]

                    finding.technique = primary_technique.technique_id
                    finding.technique_name = primary_technique.technique_name
                    finding.tactic = primary_technique.tactic

                advanced_linux_findings.append(finding)

        linux_findings.extend(advanced_linux_findings)

        linux_execution_statistics = (generate_linux_execution_statistics(
            linux_executions,advanced_linux_findings,))
        
    else:
        linux_execution_statistics = (generate_linux_execution_statistics([],[],))   

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
        linux_execution_statistics=linux_execution_statistics,
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