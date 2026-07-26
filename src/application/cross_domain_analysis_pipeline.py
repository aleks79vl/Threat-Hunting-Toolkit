from dataclasses import dataclass

from src.correlation.apache_nginx_correlation import (
    correlate_apache_nginx_findings,
)
from src.correlation.firewall_web_correlation import (
    correlate_firewall_and_web_findings,
)
from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.correlation.risk_scoring import calculate_risk_score
from src.intelligence.ioc_matcher import enrich_finding_with_ioc
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.threat_finding import ThreatFinding


@dataclass(frozen=True, slots=True)
class CrossDomainAnalysisResult:
    findings: list[ThreatFinding]
    web_correlation_findings: list[ThreatFinding]
    ioc_web_correlation_findings: list[ThreatFinding]


def run_cross_domain_analysis_pipeline(
    *,
    nmap_findings: list[ThreatFinding],
    windows_findings: list[ThreatFinding],
    firewall_findings: list[ThreatFinding],
    web_findings: list[ThreatFinding],
    web_infrastructure_findings: list[ThreatFinding],
    network_findings: list[ThreatFinding],
    linux_findings: list[ThreatFinding],
    physical_findings: list[ThreatFinding],
    risk_scores_file: str,
) -> CrossDomainAnalysisResult:
    apache_nginx_correlation_findings = (
        correlate_apache_nginx_findings(
            web_infrastructure_findings
        )
    )

    firewall_web_correlation_findings = (
        correlate_firewall_and_web_findings(
            firewall_findings
            + web_findings
            + web_infrastructure_findings
        )
    )

    web_correlation_findings = (
        apache_nginx_correlation_findings
        + firewall_web_correlation_findings
    )

    all_findings = (
        nmap_findings
        + windows_findings
        + firewall_findings
        + web_findings
        + web_infrastructure_findings
        + web_correlation_findings
        + network_findings
        + linux_findings
        + physical_findings
    )

    scored_findings = [
        calculate_risk_score(
            finding,
            risk_scores_file,
        )
        for finding in all_findings
    ]

    enriched_findings = []

    for finding in scored_findings:
        finding = enrich_finding_with_ioc(finding)
        finding = apply_ioc_risk_score(finding)

        enriched_findings.append(finding)

    ioc_web_correlation_findings = (
        correlate_ioc_and_web_findings(enriched_findings)
    )

    scored_ioc_web_correlation_findings = [
        apply_ioc_risk_score(
            calculate_risk_score(
                finding,
                risk_scores_file,
            )
        )
        for finding in ioc_web_correlation_findings
    ]

    enriched_findings.extend(
        scored_ioc_web_correlation_findings
    )

    return CrossDomainAnalysisResult(
        findings=enriched_findings,
        web_correlation_findings=web_correlation_findings,
        ioc_web_correlation_findings=(
            ioc_web_correlation_findings
        ),
    )