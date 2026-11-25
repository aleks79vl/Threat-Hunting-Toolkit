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


_DATABASE_IOC_TYPES = frozenset({
    "ip", "domain", "url", "hash",
})


def _finding_ioc_records(
    finding: ThreatFinding,
) -> list[dict[str, str]]:
    """Use currently matched feed evidence for correlation."""

    if not finding.ioc_match:
        return []

    from src.intelligence.ioc_matcher import match_iocs

    verified = match_iocs(finding)

    if not finding.ioc_matches:
        verified = [
            ioc for ioc in verified
            if (
                ioc.ioc_type == finding.ioc_type
                and ioc.value == finding.ioc_value
            )
        ]

    records = []
    seen = set()

    for ioc in verified:
        identity = (ioc.ioc_type, ioc.value)

        if identity in seen:
            continue

        seen.add(identity)
        records.append({
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "source": ioc.source,
            "description": ioc.description,
        })

    return records


def correlate_ioc_and_web_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    findings_by_ioc = defaultdict(list)

    for finding in findings:
        if not _is_web_finding(finding):
            continue

        for ioc in _finding_ioc_records(finding):
            key = (
                finding.ip,
                ioc["ioc_type"],
                ioc["value"],
            )

            findings_by_ioc[key].append((finding, ioc))

    correlated_findings = []

    for (
        client_ip,
        ioc_type,
        ioc_value,
    ), related in findings_by_ioc.items():
        related_findings = [
            finding for finding, _ in related
        ]

        first_finding, first_ioc = related[0]

        correlated_finding = ThreatFinding(
                title=(
                    "Known Malicious IOC Observed in Web Activity"
                ),
                severity=_correlation_severity(
                    related_findings
                ),
                description=(
                    f"IOC {ioc_type!r} with value {ioc_value!r} "
                    f"matched {len(related_findings)} web finding(s)."
                ),
                source="IOC + Web Correlation",
                ip=client_ip,
                hostname=first_finding.hostname,
                recommendation=(
                    "Investigate the related web activity and block "
                    "or monitor the matched IOC according to its "
                    "confidence and source."
                ),
                ioc_match=True,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                ioc_confidence=first_ioc["confidence"],
                ioc_source=first_ioc["source"],
                ioc_description=first_ioc["description"],
            )

        # Runtime-only provenance; never copied to JSON/HTML.
        correlated_finding._core08_correlation_sources = tuple(
            source_finding for source_finding, _ in related
        )

        correlated_findings.append(correlated_finding)

    return correlated_findings
