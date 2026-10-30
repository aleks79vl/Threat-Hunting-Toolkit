import re
from collections import defaultdict
from datetime import datetime, timezone

from src.models.threat_finding import ThreatFinding


ISO_TIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def _normalize_finding_time(
    value: str | None,
) -> tuple[tuple[datetime, int], str] | None:
    """
    Normalize an ISO 8601 timestamp to UTC.

    Preserve up to nine fractional digits for
    nanosecond-precision comparisons.
    """

    if not isinstance(value, str):
        return None

    match = ISO_TIME_PATTERN.fullmatch(value)

    if match is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            return None

        utc_second = parsed.astimezone(
            timezone.utc
        ).replace(microsecond=0)

        fraction = match.group("fraction")

        nanoseconds = (
            int(fraction.ljust(9, "0"))
            if fraction
            else 0
        )

        iso_time = utc_second.isoformat(
            timespec="seconds"
        )

        if fraction:
            iso_time = iso_time.replace(
                "+00:00",
                f".{fraction}+00:00",
            )

        return (utc_second, nanoseconds), iso_time

    except (ValueError, OverflowError):
        return None


def _correlated_time_range(
    findings: list[ThreatFinding],
) -> tuple[str | None, str | None]:
    """
    Merge the time ranges of contributing findings.

    Return unknown bounds if a contributing finding
    has missing, invalid, or inconsistent timestamps.
    """

    if not findings:
        return None, None

    earliest = None
    latest = None

    for finding in findings:
        first = _normalize_finding_time(
            finding.first_seen
        )
        last = _normalize_finding_time(
            finding.last_seen
        )

        if first is None or last is None:
            return None, None

        if first[0] > last[0]:
            return None, None

        if earliest is None or first[0] < earliest[0]:
            earliest = first

        if latest is None or last[0] > latest[0]:
            latest = last

    return earliest[1], latest[1]


def correlate_network_findings(
    findings: list[ThreatFinding],
) -> list[ThreatFinding]:
    """
    Correlate network findings by IP address.

    Preserve the time ranges of the findings
    contributing to each correlation.
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

        has_unknown_ip = (
            "Unknown Network IP Detected" in titles
        )
        has_critical_port = (
            "Critical Network Port Detected" in titles
        )
        has_ioc_match = (
            "Network IOC Match Detected" in titles
        )
        has_arp_spoofing = (
            "Possible ARP Spoofing Detected" in titles
        )
        has_dns_activity = any(
            "DNS" in title
            for title in titles
        )

        # Network Threat Correlation
        if (
            has_unknown_ip and has_critical_port
        ) or has_ioc_match:

            triggering_titles = set()

            if has_unknown_ip and has_critical_port:
                triggering_titles.update({
                    "Unknown Network IP Detected",
                    "Critical Network Port Detected",
                })

            if has_ioc_match:
                triggering_titles.add(
                    "Network IOC Match Detected"
                )

            contributing_findings = [
                finding
                for finding in related_findings
                if finding.title in triggering_titles
            ]

            first_seen, last_seen = _correlated_time_range(
                contributing_findings
            )

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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

        # ARP + DNS MITM Correlation
        if has_arp_spoofing and has_dns_activity:

            contributing_findings = [
                finding
                for finding in related_findings
                if (
                    finding.title
                    == "Possible ARP Spoofing Detected"
                    or "DNS" in finding.title
                )
            ]

            first_seen, last_seen = _correlated_time_range(
                contributing_findings
            )

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
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    return correlated_findings
