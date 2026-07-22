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


def _highest_severity(
    findings: list[ThreatFinding],
) -> str:
    severities = {
        finding.severity.lower()
        for finding in findings
    }

    if "critical" in severities:
        return "critical"

    if "high" in severities:
        return "high"

    return "medium"


def correlate_firewall_and_web_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    firewall_findings_by_ip = defaultdict(list)
    web_findings_by_ip = defaultdict(list)

    for finding in findings:
        if not finding.ip:
            continue

        if finding.source == "Firewall Detector":
            firewall_findings_by_ip[finding.ip].append(
                finding
            )

        if _is_web_finding(finding):
            web_findings_by_ip[finding.ip].append(finding)

    correlated_findings = []

    shared_ips = (
        firewall_findings_by_ip.keys()
        & web_findings_by_ip.keys()
    )

    for client_ip in sorted(shared_ips):
        firewall_findings = firewall_findings_by_ip[
            client_ip
        ]
        web_findings = web_findings_by_ip[client_ip]

        source_findings = firewall_findings + web_findings

        correlated_findings.append(
            ThreatFinding(
                title="Correlated Firewall and Web Attack Activity",
                severity=_highest_severity(source_findings),
                description=(
                    f"IP address {client_ip!r} generated "
                    f"{len(firewall_findings)} firewall finding(s) "
                    f"and {len(web_findings)} web finding(s)."
                ),
                source="Firewall + Web Correlation",
                ip=client_ip,
                recommendation=(
                    "Review firewall and web logs together, then "
                    "block or investigate the source IP."
                ),
            )
        )

    return correlated_findings