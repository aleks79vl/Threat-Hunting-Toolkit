from src.application.traditional_detection_pipeline import (
    run_traditional_detection_pipeline,
)
from src.application.web_infrastructure_application_pipeline import (
    run_web_infrastructure_application_pipeline,
)
from src.application.physical_security_application_pipeline import (
    run_physical_security_application_pipeline,
)
from src.application.cross_domain_analysis_pipeline import (
    run_cross_domain_analysis_pipeline,
)
from src.application.threat_report_builder import (
    build_threat_report,
)
from src.detection.network.network_pipeline import (
    run_network_detection_pipeline,
)
from src.detection.linux.linux_pipeline import (
    run_linux_detection_pipeline,
)

from src.reporting.json_report_generator import generate_json_report
from src.reporting.html_report_generator import generate_html_report
from src.reporting.console_summary import print_console_summary
from src.config.app_config import AppConfig, default_app_config


def main(
    config: AppConfig | None = None,
) -> None:
    if config is None:
        config = default_app_config()

    # Input files

    nmap_file = config.nmap_file
    windows_events_file = config.windows_events_file
    firewall_file = config.firewall_file
    web_log_file = config.web_log_file
    apache_vhost_log_file = config.apache_vhost_log_file
    apache_error_log_file = config.apache_error_log_file
    nginx_access_log_file = config.nginx_access_log_file
    nginx_error_log_file = config.nginx_error_log_file
    api_gateway_log_file = config.api_gateway_log_file
    haproxy_log_file = config.haproxy_log_file
    waf_cdn_log_file = config.waf_cdn_log_file
    pcap_file = config.pcap_file
    pcap_csv_file = config.pcap_csv_file
    linux_auth_file = config.linux_auth_file
    linux_syslog_file = config.linux_syslog_file
    physical_events_file = config.physical_events_file

    # Configuration files

    whitelist_file = config.whitelist_file
    critical_ports_file = config.critical_ports_file
    risk_scores_file = config.risk_scores_file
    web_security_baseline_file = config.web_security_baseline_file
    json_output_file = config.json_output_file
    html_output_file = config.html_output_file

    # Traditional log sources

    traditional_result = run_traditional_detection_pipeline(
        nmap_file=nmap_file,
        windows_events_file=windows_events_file,
        firewall_file=firewall_file,
        web_log_file=web_log_file,
        whitelist_file=whitelist_file,
        critical_ports_file=critical_ports_file,
    )

    nmap_findings = traditional_result.nmap_findings
    windows_findings = traditional_result.windows_findings
    firewall_events = traditional_result.firewall_events
    firewall_findings = traditional_result.firewall_findings
    web_findings = traditional_result.web_findings

    web_infrastructure_result = (
        run_web_infrastructure_application_pipeline(
            apache_access_log_file=web_log_file,
            apache_vhost_log_file=apache_vhost_log_file,
            apache_error_log_file=apache_error_log_file,
            nginx_access_log_file=nginx_access_log_file,
            nginx_error_log_file=nginx_error_log_file,
            api_gateway_log_file=api_gateway_log_file,
            haproxy_log_file=haproxy_log_file,
            waf_cdn_log_file=waf_cdn_log_file,
            web_security_baseline_file=(
                web_security_baseline_file
            ),
        )
    )

    web_infrastructure_findings = (
        web_infrastructure_result.findings
    )

    # PCAP / Wireshark pipeline

    network_result = run_network_detection_pipeline(
        pcap_file=pcap_file,
        pcap_csv_file=pcap_csv_file,
        whitelist_file=whitelist_file,
        critical_ports_file=critical_ports_file,
    )

    network_events = network_result.events
    network_findings = network_result.findings


    # Linux Log Pipeline

    linux_result = run_linux_detection_pipeline(
        linux_auth_file=linux_auth_file,
        linux_syslog_file=linux_syslog_file,
    )

    linux_events = linux_result.events
    linux_findings = linux_result.findings
    linux_statistics = linux_result.statistics[
        "linux_statistics"
    ]
    linux_execution_statistics = linux_result.statistics[
        "linux_execution_statistics"
    ]

    # Physical Security Pipeline

    physical_result = (
        run_physical_security_application_pipeline(
            physical_events_file=physical_events_file,
        )
    )

    physical_findings = (
        physical_result.all_findings
    )

    cross_domain_analysis_result = (
        run_cross_domain_analysis_pipeline(
            nmap_findings=nmap_findings,
            windows_findings=windows_findings,
            firewall_findings=firewall_findings,
            web_findings=web_findings,
            web_infrastructure_findings=(
                web_infrastructure_findings
            ),
            network_findings=network_findings,
            linux_findings=linux_findings,
            physical_findings=physical_findings,
            risk_scores_file=risk_scores_file,
        )
    )

    enriched_findings = (
        cross_domain_analysis_result.findings
    )

    # Reporting data

    report = build_threat_report(
        findings=enriched_findings,
        network_statistics=network_result.statistics,
        linux_statistics=linux_statistics,
        linux_execution_statistics=(
            linux_execution_statistics
        ),
        web_infrastructure_statistics=(
            web_infrastructure_result.event_statistics()
        ),
        physical_statistics=physical_result.statistics,
        physical_risk_score=physical_result.risk_score,
    )

    # Report generation

    generate_json_report(
        report,
        json_output_file,
    )

    generate_html_report(
        report,
        html_output_file,
    )

    # Console summary

    print_console_summary(
        report,
        json_output_file=json_output_file,
        html_output_file=html_output_file,
        network_event_count=len(network_events),
        network_finding_count=len(network_findings),
        linux_event_count=len(linux_events),
        linux_finding_count=len(linux_findings),
        physical_event_count=len(physical_result.events),
        physical_finding_count=len(physical_findings),
        physical_policy_finding_count=len(
            physical_result.policy_findings
        ),
        physical_correlation_finding_count=len(
            physical_result.correlation_findings
        ),
        physical_risk_score=physical_result.risk_score,
    )


if __name__ == "__main__":
    main()