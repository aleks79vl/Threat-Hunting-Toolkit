from collections import defaultdict

from src.models.threat_finding import ThreatFinding


WEB_SOURCE_PREFIXES = (
    "Apache",
    "API",
    "Backend",
    "Cache",
    "HAProxy",
    "Header",
    "HTTP",
    "Load Balancer",
    "Nginx",
    "Reverse Proxy",
    "SSRF",
    "TLS",
    "WAF",
    "Web Attack",
    "WebSocket",
)


def _is_web_finding(finding: ThreatFinding) -> bool:
    return finding.source.startswith(
        WEB_SOURCE_PREFIXES
    )


def _correlation_severity(
    findings: list[ThreatFinding],
) -> str:
    if any(
        finding.severity.lower() == "critical"
        for finding in findings
    ):
        return "critical"

    return "high"


def correlate_ioc_and_web_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    findings_by_ioc = defaultdict(list)

    for finding in findings:
        if not _is_web_finding(finding):
            continue

        if not finding.ioc_match:
            continue

        if not finding.ioc_type or not finding.ioc_value:
            continue

        correlation_key = (
            finding.ip,
            finding.ioc_type,
            finding.ioc_value,
        )

        findings_by_ioc[correlation_key].append(finding)

    correlated_findings = []

    for (
        client_ip,
        ioc_type,
        ioc_value,
    ), related_findings in findings_by_ioc.items():
        correlated_findings.append(
            ThreatFinding(
                title=(
                    "Known Malicious IOC Observed in Web Activity"
                ),
                severity=_correlation_severity(related_findings),
                description=(
                    f"IOC {ioc_type!r} with value {ioc_value!r} "
                    f"matched {len(related_findings)} web finding(s)."
                ),
                source="IOC + Web Correlation",
                ip=client_ip,
                hostname=related_findings[0].hostname,
                recommendation=(
                    "Investigate the related web activity and block "
                    "or monitor the matched IOC according to its "
                    "confidence and source."
                ),
                ioc_match=True,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                ioc_confidence=related_findings[
                    0
                ].ioc_confidence,
                ioc_source=related_findings[0].ioc_source,
                ioc_description=related_findings[
                    0
                ].ioc_description,
            )
        )

    return correlated_findings