from src.correlation.network_correlation import (
    correlate_network_findings,
)
from src.models.threat_finding import ThreatFinding


def create_finding(
    title: str,
    ip: str,
    severity: str = "medium",
) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity=severity,
        description="test",
        source="Unit Test",
        ip=ip,
        recommendation="Investigate",
    )


def test_correlate_unknown_ip_and_critical_port():
    findings = [
        create_finding(
            "Unknown Network IP Detected",
            "10.0.0.50",
        ),
        create_finding(
            "Critical Network Port Detected",
            "10.0.0.50",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Correlated Network Threat Detected"
    assert correlated[0].severity == "critical"
    assert correlated[0].ip == "10.0.0.50"


def test_correlate_ioc_match():
    findings = [
        create_finding(
            "Network IOC Match Detected",
            "185.220.101.1",
            severity="high",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Correlated Network Threat Detected"


def test_correlate_arp_and_dns_activity():
    findings = [
        create_finding(
            "Possible ARP Spoofing Detected",
            "10.0.0.1",
            severity="high",
        ),
        create_finding(
            "Repeated DNS Query Activity Detected",
            "10.0.0.1",
            severity="medium",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Possible MITM Activity Correlated"
    assert correlated[0].severity == "critical"


def test_do_not_correlate_single_unknown_ip():
    findings = [
        create_finding(
            "Unknown Network IP Detected",
            "10.0.0.50",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert correlated == []


def test_ignore_findings_without_ip():
    findings = [
        ThreatFinding(
            title="Unknown Network IP Detected",
            severity="medium",
            description="test",
            source="Unit Test",
            recommendation="Investigate",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert correlated == []


def create_timed_finding(
    title: str,
    ip: str,
    first_seen: str | None,
    last_seen: str | None,
) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity="high",
        description="test",
        source="Unit Test",
        ip=ip,
        recommendation="Investigate",
        first_seen=first_seen,
        last_seen=last_seen,
    )


def test_network_correlation_preserves_trigger_time_range():
    findings = [
        create_timed_finding(
            "Critical Network Port Detected",
            "10.0.0.50",
            "2026-07-16T09:05:00+00:00",
            "2026-07-16T09:07:00.987654321+00:00",
        ),
        create_timed_finding(
            "Long DNS Query Detected",
            "10.0.0.50",
            "2026-07-16T06:00:00+00:00",
            "2026-07-16T06:01:00+00:00",
        ),
        create_timed_finding(
            "Unknown Network IP Detected",
            "10.0.0.50",
            "2026-07-16T09:00:00.123456789+00:00",
            "2026-07-16T09:03:00+00:00",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == (
        "Correlated Network Threat Detected"
    )
    assert correlated[0].first_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    assert correlated[0].last_seen == (
        "2026-07-16T09:07:00.987654321+00:00"
    )


def test_ioc_correlation_preserves_nanosecond_precision():
    findings = [
        create_timed_finding(
            "Network IOC Match Detected",
            "185.220.101.1",
            "2026-07-16T09:00:00.123456789+00:00",
            "2026-07-16T09:00:00.123456789+00:00",
        ),
        create_timed_finding(
            "Unknown Network IP Detected",
            "185.220.101.1",
            "2026-07-16T06:00:00+00:00",
            "2026-07-16T06:00:00+00:00",
        ),
        create_timed_finding(
            "Network IOC Match Detected",
            "185.220.101.1",
            "2026-07-16T09:00:00.123456788+00:00",
            "2026-07-16T09:00:00.123456788+00:00",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1

    assert correlated[0].first_seen == (
        "2026-07-16T09:00:00.123456788+00:00"
    )
    assert correlated[0].last_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )


def test_network_correlations_keep_independent_time_ranges():
    ip = "10.0.0.1"

    findings = [
        create_timed_finding(
            "Network IOC Match Detected",
            ip,
            "2026-07-16T11:00:00+00:00",
            "2026-07-16T11:01:00+00:00",
        ),
        create_timed_finding(
            "Repeated DNS Query Activity Detected",
            ip,
            "2026-07-16T09:00:00+00:00",
            "2026-07-16T09:05:00+00:00",
        ),
        create_timed_finding(
            "Possible ARP Spoofing Detected",
            ip,
            "2026-07-16T08:00:00+00:00",
            "2026-07-16T08:10:00+00:00",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 2

    by_title = {
        finding.title: finding
        for finding in correlated
    }

    network_threat = by_title[
        "Correlated Network Threat Detected"
    ]

    mitm_threat = by_title[
        "Possible MITM Activity Correlated"
    ]

    assert network_threat.first_seen == (
        "2026-07-16T11:00:00+00:00"
    )
    assert network_threat.last_seen == (
        "2026-07-16T11:01:00+00:00"
    )

    assert mitm_threat.first_seen == (
        "2026-07-16T08:00:00+00:00"
    )
    assert mitm_threat.last_seen == (
        "2026-07-16T09:05:00+00:00"
    )


def test_network_correlation_does_not_invent_missing_time():
    findings = [
        create_timed_finding(
            "Possible ARP Spoofing Detected",
            "10.0.0.1",
            "2026-07-16T09:00:00+00:00",
            "2026-07-16T09:05:00+00:00",
        ),
        create_timed_finding(
            "Repeated DNS Query Activity Detected",
            "10.0.0.1",
            None,
            "2026-07-16T09:10:00+00:00",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == (
        "Possible MITM Activity Correlated"
    )

    assert correlated[0].first_seen is None
    assert correlated[0].last_seen is None
