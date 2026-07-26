from src.application.cross_domain_analysis_pipeline import (
    run_cross_domain_analysis_pipeline,
)
from src.config.app_config import default_app_config
from src.models.threat_finding import ThreatFinding


def _finding(source: str) -> ThreatFinding:
    return ThreatFinding(
        title="Test Finding",
        severity="high",
        description="Synthetic finding for pipeline testing.",
        source=source,
        ip="198.51.100.250",
        hostname="web.example.test",
    )


def test_cross_domain_analysis_creates_web_correlations():
    config = default_app_config()

    result = run_cross_domain_analysis_pipeline(
        nmap_findings=[],
        windows_findings=[],
        firewall_findings=[
            _finding("Firewall Detector"),
        ],
        web_findings=[
            _finding("Web Attack Detector"),
        ],
        web_infrastructure_findings=[
            _finding("Apache Test Detector"),
            _finding("Nginx Test Detector"),
        ],
        network_findings=[],
        linux_findings=[],
        physical_findings=[],
        risk_scores_file=config.risk_scores_file,
    )

    assert len(result.web_correlation_findings) == 2
    assert result.ioc_web_correlation_findings == []
    assert len(result.findings) == 6