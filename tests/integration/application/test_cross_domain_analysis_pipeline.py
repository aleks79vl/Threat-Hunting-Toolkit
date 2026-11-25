from src.application.cross_domain_analysis_pipeline import (
    run_cross_domain_analysis_pipeline,
)
from src.config.app_config import default_app_config
from src.models.threat_finding import ThreatFinding
from src.models.ioc import IOC
from src.intelligence import ioc_matcher


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


def test_cross_domain_preserves_advanced_linux_risk_score():
    config = default_app_config()

    linux_finding = ThreatFinding(
        title="Linux Reverse Shell Detected",
        severity="high",
        description="Observed reverse shell process.",
        source="Linux Host Detection",
        risk_score=95,
        risk_score_base=95,
        risk_base_sources={"linux_advanced": 95},
    )

    result = run_cross_domain_analysis_pipeline(
        nmap_findings=[],
        windows_findings=[],
        firewall_findings=[],
        web_findings=[],
        web_infrastructure_findings=[],
        network_findings=[],
        linux_findings=[linux_finding],
        physical_findings=[],
        risk_scores_file=config.risk_scores_file,
    )

    assert len(result.findings) == 1
    assert result.findings[0].risk_score == 95


def test_cross_domain_preserves_linux_score_with_repeated_ioc_enrichment(
    monkeypatch,
):
    config = default_app_config()

    linux_finding = ThreatFinding(
        title="Suspicious Linux Process Execution Detected",
        severity="high",
        description="Observed suspicious process execution.",
        ip="203.0.113.20",
        source="Linux Host Detection",
        risk_score=65,
        risk_score_base=65,
        risk_base_sources={"linux_advanced": 65},
    )

    indicator = IOC(
        value="203.0.113.20",
        ioc_type="ip",
        source="CORE-08 Integration Test Feed",
        confidence="medium",
        description="Synthetic Linux IOC",
    )

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
    )

    def run_analysis():
        return run_cross_domain_analysis_pipeline(
            nmap_findings=[],
            windows_findings=[],
            firewall_findings=[],
            web_findings=[],
            web_infrastructure_findings=[],
            network_findings=[],
            linux_findings=[linux_finding],
            physical_findings=[],
            risk_scores_file=config.risk_scores_file,
        )

    first_result = run_analysis()
    first_finding = first_result.findings[0]

    assert first_finding.risk_score_base == 65
    assert first_finding.risk_factors["ioc"] == 20
    assert first_finding.risk_score == 85

    second_result = run_analysis()
    second_finding = second_result.findings[0]

    assert second_finding.risk_score_base == 65
    assert second_finding.risk_factors == {"ioc": 20}
    assert second_finding.risk_score == 85
