from pathlib import Path

from src.correlation.network_correlation import correlate_network_findings
from src.detection.network.dns_activity_detector import (
    detect_suspicious_dns_activity,
)
from src.detection.network.mitm_detector import detect_arp_spoofing
from src.detection.network.network_ioc_detector import detect_network_iocs
from src.detection.network.network_web_attack_detector import (
    detect_network_web_attacks,
)
from src.detection.network.packet_anomaly_detector import (
    detect_packet_anomalies,
)
from src.detection.nmap.network_critical_port_detector import (
    detect_network_critical_ports,
)
from src.detection.nmap.network_unknown_ip_detector import (
    detect_unknown_network_ips,
)
from src.models.domain_pipeline_result import DomainPipelineResult
from src.parsers.pcap_exporter import export_pcap_to_csv
from src.parsers.wireshark_csv_parser import parse_wireshark_csv
from src.reporting.network_statistics import generate_network_statistics


def run_network_detection_pipeline(
    pcap_file: str,
    pcap_csv_file: str,
    whitelist_file: str,
    critical_ports_file: str,
) -> DomainPipelineResult:
    network_events = []
    network_findings = []

    if Path(pcap_file).exists():
        export_pcap_to_csv(
            pcap_file,
            pcap_csv_file,
        )

        network_events = parse_wireshark_csv(
            pcap_csv_file
        )

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

        network_findings.extend(
            detect_network_iocs(network_events)
        )

        network_findings.extend(
            detect_network_web_attacks(network_events)
        )

        network_findings.extend(
            detect_suspicious_dns_activity(network_events)
        )

        network_findings.extend(
            detect_packet_anomalies(network_events)
        )

        network_findings.extend(
            detect_arp_spoofing(network_events)
        )

        network_findings.extend(
            correlate_network_findings(
                network_findings
            )
        )

    return DomainPipelineResult(
        events=network_events,
        findings=network_findings,
        statistics=generate_network_statistics(
            network_events
        ),
    )