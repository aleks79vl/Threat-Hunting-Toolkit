from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AppConfig:
    nmap_file: str
    windows_events_file: str
    firewall_file: str
    web_log_file: str
    apache_vhost_log_file: str
    apache_error_log_file: str
    nginx_access_log_file: str
    nginx_error_log_file: str
    api_gateway_log_file: str
    haproxy_log_file: str
    waf_cdn_log_file: str
    pcap_file: str
    pcap_csv_file: str
    linux_auth_file: str
    linux_syslog_file: str
    physical_events_file: str
    whitelist_file: str
    critical_ports_file: str
    risk_scores_file: str
    web_security_baseline_file: str
    json_output_file: str
    html_output_file: str


def default_app_config() -> AppConfig:
    return AppConfig(
        nmap_file="data/raw/network/nmap_scan.xml",
        windows_events_file="data/raw/windows/security_events.csv",
        firewall_file="data/raw/firewall/firewall.log",
        web_log_file="data/raw/web/apache_access.log",
        apache_vhost_log_file="data/raw/web/apache_vhost_access.log",
        apache_error_log_file="data/raw/web/apache_error.log",
        nginx_access_log_file="data/raw/web/nginx_access.jsonl",
        nginx_error_log_file="data/raw/web/nginx_error.log",
        api_gateway_log_file="data/raw/web/api_gateway_access.jsonl",
        haproxy_log_file="data/raw/web/haproxy_http.log",
        waf_cdn_log_file="data/raw/web/waf_cdn_events.jsonl",
        pcap_file="data/raw/pcap/sample.pcap",
        pcap_csv_file="data/processed/pcap/sample.csv",
        linux_auth_file="data/raw/linux/auth.log",
        linux_syslog_file="data/raw/linux/syslog",
        physical_events_file="data/raw/physical/sample_physical_events.json",
        whitelist_file="config/whitelist.json",
        critical_ports_file="config/critical_ports.json",
        risk_scores_file="config/risk_scores.json",
        web_security_baseline_file="config/web_security_baseline.json",
        json_output_file="reports/threat_report.json",
        html_output_file="reports/threat_report.html",
    )