from src.detection.web.tls_metadata_detector import (
    detect_tls_metadata_anomalies,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    tls_version: str,
    sni: str,
    host: str = "api.example.com",
    server_port: int = 443,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T11:00:00Z",
        source="waf_cdn",
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/profile",
        status_code=200,
        host=host,
        virtual_host=host,
        server_port=server_port,
        tls_version=tls_version,
        sni=sni,
    )


def test_detects_weak_tls_version():
    findings = detect_tls_metadata_anomalies(
        [
            make_event(
                tls_version="TLSv1.1",
                sni="api.example.com",
            )
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Weak TLS Version Detected"
    assert findings[0].severity == "high"


def test_detects_sni_and_host_mismatch():
    findings = detect_tls_metadata_anomalies(
        [
            make_event(
                tls_version="TLSv1.3",
                sni="admin.example.com",
                host="api.example.com",
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "TLS SNI and Host Header Mismatch"
    )


def test_detects_missing_tls_metadata_on_https_port():
    findings = detect_tls_metadata_anomalies(
        [
            make_event(
                tls_version="",
                sni="",
                server_port=443,
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Missing TLS Metadata on HTTPS Port"
    )


def test_ignores_secure_matching_tls_event():
    findings = detect_tls_metadata_anomalies(
        [
            make_event(
                tls_version="TLSv1.3",
                sni="api.example.com",
            )
        ]
    )

    assert findings == []