from collections import defaultdict

from src.models.threat_finding import ThreatFinding


def _is_apache_finding(finding: ThreatFinding) -> bool:
    return finding.source.startswith("Apache")


def _is_nginx_finding(finding: ThreatFinding) -> bool:
    return finding.source.startswith("Nginx")


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


def correlate_apache_nginx_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    apache_findings_by_ip = defaultdict(list)
    nginx_findings_by_ip = defaultdict(list)

    for finding in findings:
        if not finding.ip:
            continue

        if _is_apache_finding(finding):
            apache_findings_by_ip[finding.ip].append(finding)

        if _is_nginx_finding(finding):
            nginx_findings_by_ip[finding.ip].append(finding)

    correlated_findings = []

    shared_ips = (
        apache_findings_by_ip.keys()
        & nginx_findings_by_ip.keys()
    )

    for client_ip in sorted(shared_ips):
        apache_findings = apache_findings_by_ip[client_ip]
        nginx_findings = nginx_findings_by_ip[client_ip]

        apache_hosts = {
            finding.hostname
            for finding in apache_findings
            if finding.hostname
        }

        nginx_hosts = {
            finding.hostname
            for finding in nginx_findings
            if finding.hostname
        }

        if (
            apache_hosts
            and nginx_hosts
            and not apache_hosts.intersection(nginx_hosts)
        ):
            continue

        matching_hosts = apache_hosts.intersection(
            nginx_hosts
        )

        hostname = (
            sorted(matching_hosts)[0]
            if matching_hosts
            else ""
        )

        source_findings = apache_findings + nginx_findings

        correlated_findings.append(
            ThreatFinding(
                title=(
                    "Correlated Web Attack Across Apache and Nginx"
                ),
                severity=_highest_severity(source_findings),
                description=(
                    f"IP address {client_ip!r} generated "
                    f"{len(apache_findings)} Apache finding(s) and "
                    f"{len(nginx_findings)} Nginx finding(s)."
                ),
                source="Apache + Nginx Correlation",
                ip=client_ip,
                hostname=hostname,
                recommendation=(
                    "Review the complete request chain across Apache "
                    "and Nginx and block or investigate the source IP."
                ),
            )
        )

    return correlated_findings