from src.application.traditional_detection_pipeline import (
    run_traditional_detection_pipeline,
)
from src.config.app_config import default_app_config
from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


def test_traditional_detection_pipeline_runs_default_sources():
    config = default_app_config()

    result = run_traditional_detection_pipeline(
        nmap_file=config.nmap_file,
        windows_events_file=config.windows_events_file,
        firewall_file=config.firewall_file,
        web_log_file=config.web_log_file,
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
    )

    assert result.firewall_events
    assert all(
        isinstance(event, SecurityEvent)
        for event in result.firewall_events
    )
    assert all(
        isinstance(finding, ThreatFinding)
        for finding in result.nmap_findings
        + result.windows_findings
        + result.firewall_findings
        + result.web_findings
    )