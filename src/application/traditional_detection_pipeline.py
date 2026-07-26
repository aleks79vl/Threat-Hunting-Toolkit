from dataclasses import dataclass

from src.correlation.threat_correlation import correlate_threats
from src.detection.firewall.firewall_detector import (
    detect_firewall_events,
)
from src.detection.nmap.critical_port_detector import (
    detect_critical_ports,
)
from src.detection.nmap.unknown_ip_detector import detect_unknown_ips
from src.detection.web.web_attack_detector import detect_web_attacks
from src.detection.windows.windows_event_detector import (
    detect_windows_events,
)
from src.models.threat_finding import ThreatFinding
from src.parsers.firewall_parser import parse_firewall_log
from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.web_log_parser import parse_web_log
from src.parsers.windows_event_parser import parse_windows_events
from src.utils.event_utils import SecurityEvent


@dataclass(frozen=True, slots=True)
class TraditionalDetectionResult:
    nmap_findings: list[ThreatFinding]
    windows_findings: list[ThreatFinding]
    firewall_events: list[SecurityEvent]
    firewall_findings: list[ThreatFinding]
    web_findings: list[ThreatFinding]


def run_traditional_detection_pipeline(
    nmap_file: str,
    windows_events_file: str,
    firewall_file: str,
    web_log_file: str,
    whitelist_file: str,
    critical_ports_file: str,
) -> TraditionalDetectionResult:
    nmap_events = parse_nmap_xml(nmap_file)

    unknown_events = detect_unknown_ips(
        nmap_events,
        whitelist_file,
    )
    critical_events = detect_critical_ports(
        nmap_events,
        critical_ports_file,
    )
    nmap_findings = correlate_threats(
        unknown_events,
        critical_events,
    )

    windows_events = parse_windows_events(windows_events_file)
    windows_findings = detect_windows_events(windows_events)

    firewall_events = parse_firewall_log(firewall_file)
    firewall_findings = detect_firewall_events(firewall_events)

    web_events = parse_web_log(web_log_file)
    web_findings = detect_web_attacks(web_events)

    return TraditionalDetectionResult(
        nmap_findings=nmap_findings,
        windows_findings=windows_findings,
        firewall_events=firewall_events,
        firewall_findings=firewall_findings,
        web_findings=web_findings,
    )