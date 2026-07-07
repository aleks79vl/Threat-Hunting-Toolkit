from collections import defaultdict

from src.models.threat_finding import ThreatFinding


def correlate_network_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    """
    Correlate network findings by IP address.
    """

    findings_by_ip = defaultdict(list)

    for finding in findings:
        if finding.ip:
            findings_by_ip[finding.ip].append(finding)

    correlated_findings = []

    for ip_address, related_findings in findings_by_ip.items():
        titles = {
            finding.title
            for finding in related_findings
        }

        has_unknown_ip = "Unknown Network IP Detected" in titles
        has_critical_port = "Critical Network Port Detected" in titles
        has_ioc_match = "Network IOC Match Detected" in titles
        has_arp_spoofing = "Possible ARP Spoofing Detected" in titles
        has_dns_activity = any(
            "DNS" in title
            for title in titles
        )

        if (
            has_unknown_ip
            and has_critical_port
        ) or has_ioc_match:
            correlated_findings.append(
                ThreatFinding(
                    title="Correlated Network Threat Detected",
                    severity="critical",
                    description=(
                        f"Multiple network detection signals were "
                        f"observed for IP address {ip_address}."
                    ),
                    source="Network Correlation Engine",
                    ip=ip_address,
                    recommendation=(
                        "Prioritize investigation of this IP address "
                        "because multiple network indicators are present."
                    ),
                )
            )

        if has_arp_spoofing and has_dns_activity:
            correlated_findings.append(
                ThreatFinding(
                    title="Possible MITM Activity Correlated",
                    severity="critical",
                    description=(
                        f"ARP anomaly and DNS activity were both "
                        f"observed for IP address {ip_address}."
                    ),
                    source="Network Correlation Engine",
                    ip=ip_address,
                    recommendation=(
                        "Investigate possible Man-in-the-Middle activity "
                        "and validate ARP/DNS behavior."
                    ),
                )
            )

    return correlated_findings