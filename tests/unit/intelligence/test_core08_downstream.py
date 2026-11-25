from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.reporting.ioc_statistics import (
    generate_ioc_statistics,
)
from src.models.threat_finding import ThreatFinding


def _ioc(ioc_type, value, confidence="high"):
    return {
        "ioc_type": ioc_type,
        "value": value,
        "source": "CORE-08 Test Feed",
        "confidence": confidence,
        "description": "Synthetic IOC",
    }


def _web_finding():
    return ThreatFinding(
        title="Web Security Observation",
        severity="high",
        description="Request to evil-example.com",
        source="WAF Security Detector",
        ip="203.0.113.99",
        hostname="evil-example.com",
        ioc_match=True,
        ioc_type="domain",
        ioc_value="evil-example.com",
        ioc_confidence="high",
        ioc_source="CORE-08 Test Feed",
        ioc_matches=[
            _ioc("domain", "evil-example.com"),
            _ioc("ip", "203.0.113.99", "medium"),
        ],
    )


def test_correlation_preserves_every_database_ioc():
    correlations = correlate_ioc_and_web_findings(
        [_web_finding()]
    )

    observed = {
        (finding.ioc_type, finding.ioc_value)
        for finding in correlations
    }

    assert observed == {
        ("domain", "evil-example.com"),
        ("ip", "203.0.113.99"),
    }

    assert len(correlations) == 2


def test_correlation_deduplicates_each_ioc_independently():
    correlations = correlate_ioc_and_web_findings(
        [_web_finding(), _web_finding()]
    )

    assert len(correlations) == 2

    assert {
        (finding.ioc_type, finding.ioc_value)
        for finding in correlations
    } == {
        ("domain", "evil-example.com"),
        ("ip", "203.0.113.99"),
    }

    assert all(
        "2 web finding(s)" in finding.description
        for finding in correlations
    )


def test_statistics_count_all_ioc_types():
    statistics = generate_ioc_statistics(
        [_web_finding()]
    )

    # Preserve the legacy meaning:
    # total_matches = number of matched findings.
    assert statistics["total_matches"] == 1

    # Type counts must include all IOC matches.
    assert statistics["domain"] == 1
    assert statistics["ip"] == 1


def test_session_identity_alone_is_not_database_ioc():
    session_finding = ThreatFinding(
        title="API Session Anomaly",
        severity="high",
        description="Abnormal session activity",
        source="API Security Detector",
        ip="203.0.113.44",
        ioc_match=True,
        ioc_type="session_id_hash",
        ioc_value="hmac-sha256:synthetic-session",
        ioc_source="API Security Detector",
    )

    correlations = correlate_ioc_and_web_findings(
        [session_finding]
    )

    assert correlations == []
