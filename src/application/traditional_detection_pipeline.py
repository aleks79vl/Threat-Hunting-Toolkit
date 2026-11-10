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

from src.utils.event_utils import SecurityEvent

from src.parsers.windows_event_parser import parse_windows_events
from src.parsers.firewall_parser import parse_firewall_log
from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.web_log_parser import parse_web_log
from src.parsers.parser_diagnostics import ParserDiagnostics

from src.application.source_failure import SourceFailure
from src.application.source_isolation import (
    parse_isolated_source_with_status,
)


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
    windows_source_timezone: str | None = None,
    firewall_source_timezone: str | None = None,
    *,
    firewall_diagnostics: ParserDiagnostics | None = None,
    source_failures: list[SourceFailure] | None = None,
) -> TraditionalDetectionResult:

    nmap_result = parse_isolated_source_with_status(
        source="nmap",
        parse=lambda: parse_nmap_xml(nmap_file),
        source_failures=source_failures,
    )

    if nmap_result.failed:
        nmap_findings = []

    else:
        unknown_events = detect_unknown_ips(
            nmap_result.events,
            whitelist_file,
        )

        critical_events = detect_critical_ports(
            nmap_result.events,
            critical_ports_file,
        )

        nmap_findings = correlate_threats(
            unknown_events,
            critical_events,
        )

    windows_result = parse_isolated_source_with_status(
        source="windows_events",
        parse=lambda: parse_windows_events(
            windows_events_file,
        ),
        source_failures=source_failures,
    )

    windows_findings = detect_windows_events(
        windows_result.events,
        source_timezone=windows_source_timezone,
    )

    firewall_result = parse_isolated_source_with_status(
        source="firewall",
        parse=lambda: parse_firewall_log(
            firewall_file,
            diagnostics=firewall_diagnostics,
        ),
        source_failures=source_failures,
    )

    firewall_events = firewall_result.events

    firewall_findings = detect_firewall_events(
        firewall_events,
        source_timezone=firewall_source_timezone,
    )

    web_result = parse_isolated_source_with_status(
        source="web_log",
        parse=lambda: parse_web_log(web_log_file),
        source_failures=source_failures,
    )

    if web_result.failed:
        # Skip Web detection when telemetry is unavailable.
        web_findings = []

    else:
        web_findings = detect_web_attacks(
            web_result.events,
        )

    return TraditionalDetectionResult(
        nmap_findings=nmap_findings,
        windows_findings=windows_findings,
        firewall_events=firewall_events,
        firewall_findings=firewall_findings,
        web_findings=web_findings,
    )
