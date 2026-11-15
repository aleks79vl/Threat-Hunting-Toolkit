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
from src.application.source_failure import SourceFailure
from src.application.input_integrity import (
    build_input_integrity,
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

from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.quarantine_buffer import QuarantineBuffer


def main(
    config: AppConfig | None = None,
) -> None:
    if config is None:
        config = default_app_config()

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


    whitelist_file = config.whitelist_file
    critical_ports_file = config.critical_ports_file
    risk_scores_file = config.risk_scores_file
    web_security_baseline_file = config.web_security_baseline_file
    json_output_file = config.json_output_file
    html_output_file = config.html_output_file

    firewall_diagnostics = ParserDiagnostics(
        source="firewall",
        quarantine=QuarantineBuffer(
            max_records=100,
            max_record_bytes=4096,
        ),
    )

    source_failures: list[SourceFailure] = []

    traditional_result = run_traditional_detection_pipeline(
        nmap_file=nmap_file,
        windows_events_file=windows_events_file,
        firewall_file=firewall_file,
        web_log_file=web_log_file,
        whitelist_file=whitelist_file,
        critical_ports_file=critical_ports_file,
        windows_source_timezone=config.windows_source_timezone,
        firewall_source_timezone=config.firewall_source_timezone,
        firewall_diagnostics=firewall_diagnostics,
        source_failures=source_failures,
    )

    nmap_findings = traditional_result.nmap_findings
    windows_findings = traditional_result.windows_findings
    firewall_events = traditional_result.firewall_events
    firewall_findings = traditional_result.firewall_findings
    web_findings = traditional_result.web_findings

    nginx_diagnostics = ParserDiagnostics(
        source="nginx",quarantine=QuarantineBuffer(
            max_records=100,
            max_record_bytes=4096,
        ),
    )

    waf_diagnostics = ParserDiagnostics(
        source="waf_cdn",
        quarantine=QuarantineBuffer(
            max_records=100,
            max_record_bytes=4096,
        ),
    )

    apache_access_diagnostics = ParserDiagnostics(
        source="apache_access",
        quarantine=QuarantineBuffer(
            max_records=100,
            max_record_bytes=4096,
        ),
    )

    apache_vhost_diagnostics = ParserDiagnostics(
        source="apache_vhost",
        quarantine=QuarantineBuffer(
            max_records=100,
            max_record_bytes=4096,
        ),
    )

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
            nginx_diagnostics=nginx_diagnostics,
            waf_diagnostics=waf_diagnostics,
            apache_access_diagnostics=apache_access_diagnostics,
            apache_vhost_diagnostics=apache_vhost_diagnostics,
            source_failures=source_failures,
        )
    )

    web_infrastructure_findings = (
        web_infrastructure_result.findings
    )

    network_result = run_network_detection_pipeline(
        pcap_file=pcap_file,
        pcap_csv_file=pcap_csv_file,
        whitelist_file=whitelist_file,
        critical_ports_file=critical_ports_file,
    )

    network_events = network_result.events
    network_findings = network_result.findings

    linux_result = run_linux_detection_pipeline(
        linux_auth_file=linux_auth_file,
        linux_syslog_file=linux_syslog_file,
        linux_auth_source_year=config.linux_auth_source_year,
        linux_auth_source_timezone=config.linux_auth_source_timezone,
        linux_syslog_source_year=config.linux_syslog_source_year,
        linux_syslog_source_timezone=config.linux_syslog_source_timezone,
    )

    linux_events = linux_result.events
    linux_findings = linux_result.findings
    linux_statistics = linux_result.statistics[
        "linux_statistics"
    ]
    linux_execution_statistics = linux_result.statistics[
        "linux_execution_statistics"
    ]


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

    input_integrity = build_input_integrity(
        source_failures=source_failures,
        parser_diagnostics=[
            firewall_diagnostics,
            nginx_diagnostics,
            waf_diagnostics,
            apache_access_diagnostics,
            apache_vhost_diagnostics,
        ],
    )

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
        input_integrity=input_integrity,
    )

    generate_json_report(
        report,
        json_output_file,
    )

    generate_html_report(
        report,
        html_output_file,
    )

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

    if firewall_diagnostics.rejected > 0:
        print()
        print("WARNING: Firewall input incomplete")

        print(
            f"read={firewall_diagnostics.read} "
            f"accepted={firewall_diagnostics.accepted} "
            f"rejected={firewall_diagnostics.rejected}"
        )

        reason_codes = sorted({
            issue.reason
            for issue in firewall_diagnostics.issues
        })

        if reason_codes:
            print(
                "Firewall rejection reasons (retained): "
                + ", ".join(reason_codes)
            )

        if firewall_diagnostics.issues_dropped > 0:
            print(
                "Firewall diagnostics omitted: "
                f"{firewall_diagnostics.issues_dropped}"
            )

    if nginx_diagnostics.rejected > 0:
        print()
        print("WARNING: Nginx input incomplete")

        print(
            f"nginx read={nginx_diagnostics.read} "
            f"accepted={nginx_diagnostics.accepted} "
            f"rejected={nginx_diagnostics.rejected}"
        )

        reason_codes = sorted({
            issue.reason
            for issue in nginx_diagnostics.issues
        })

        if reason_codes:
            print(
                "Nginx rejection reasons (retained): "
                + ", ".join(reason_codes)
            )

        if nginx_diagnostics.issues_dropped > 0:
            print(
                "Nginx diagnostics omitted: "
                f"{nginx_diagnostics.issues_dropped}"
            )

    if waf_diagnostics.rejected > 0:
        print()
        print("WARNING: WAF input incomplete")

        print(
            f"waf_cdn read={waf_diagnostics.read} "
            f"accepted={waf_diagnostics.accepted} "
            f"rejected={waf_diagnostics.rejected}"
        )

        reason_codes = sorted({
            issue.reason
            for issue in waf_diagnostics.issues
        })

        if reason_codes:
            print(
                "WAF rejection reasons (retained): "
                + ", ".join(reason_codes)
            )

        if waf_diagnostics.issues_dropped > 0:
            print(
                "WAF diagnostics omitted: "
                f"{waf_diagnostics.issues_dropped}"
            )

    if apache_access_diagnostics.rejected > 0:
        print()
        print("WARNING: Apache Access input incomplete")

        print(
            f"apache_access read={apache_access_diagnostics.read} "
            f"accepted={apache_access_diagnostics.accepted} "
            f"rejected={apache_access_diagnostics.rejected}"
        )

        reason_codes = sorted({
            issue.reason
            for issue in apache_access_diagnostics.issues
        })

        if reason_codes:
            print(
                "Apache Access rejection reasons (retained): "
                + ", ".join(reason_codes)
            )

        if apache_access_diagnostics.issues_dropped > 0:
            print(
                "Apache Access diagnostics omitted: "
                f"{apache_access_diagnostics.issues_dropped}"
            )

    if apache_vhost_diagnostics.rejected > 0:
        print()
        print("WARNING: Apache VHost input incomplete")

        print(
            f"apache_vhost read={apache_vhost_diagnostics.read} "
            f"accepted={apache_vhost_diagnostics.accepted} "
            f"rejected={apache_vhost_diagnostics.rejected}"
        )

        reason_codes = sorted({
            issue.reason
            for issue in apache_vhost_diagnostics.issues
        })

        if reason_codes:
            print(
                "Apache VHost rejection reasons (retained): "
                + ", ".join(reason_codes)
            )

        if apache_vhost_diagnostics.issues_dropped > 0:
            print(
                "Apache VHost diagnostics omitted: "
                f"{apache_vhost_diagnostics.issues_dropped}"
            )

    if source_failures:
        print()
        print("WARNING: Web source unavailable")

        for failure in source_failures:
            print(
                f"source={failure.source} "
                f"reason={failure.reason}"
            )


if __name__ == "__main__":
    main()