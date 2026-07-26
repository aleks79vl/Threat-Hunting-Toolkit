from datetime import datetime

from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.timeline_generator import generate_timeline


def build_threat_report(
    *,
    findings: list[ThreatFinding],
    network_statistics: dict,
    linux_statistics: dict,
    linux_execution_statistics: dict,
    web_infrastructure_statistics: dict,
    physical_statistics: dict,
    physical_risk_score: int,
    title: str = "Threat Hunting Report",
    generated_at: str | None = None,
) -> ThreatReport:
    if generated_at is None:
        generated_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    return ThreatReport(
        title=title,
        generated_at=generated_at,
        findings=findings,
        timeline=generate_timeline(findings),
        network_statistics=network_statistics,
        linux_statistics=linux_statistics,
        linux_execution_statistics=(
            linux_execution_statistics
        ),
        web_infrastructure_statistics=(
            web_infrastructure_statistics
        ),
        physical_statistics=physical_statistics,
        physical_risk_score=physical_risk_score,
    )