from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


WEAK_TLS_VERSIONS = {
    "sslv2",
    "sslv3",
    "tlsv1",
    "tlsv1.0",
    "tlsv1.1",
}


def _normalize_hostname(value: str) -> str:
    return value.lower().split(":", maxsplit=1)[0].rstrip(".")


def detect_tls_metadata_anomalies(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        normalized_tls_version = event.tls_version.lower()

        if normalized_tls_version in WEAK_TLS_VERSIONS:
            findings.append(
                ThreatFinding(
                    title="Weak TLS Version Detected",
                    severity="high",
                    description=(
                        f"Request to {event.host!r} used deprecated "
                        f"TLS version {event.tls_version!r}."
                    ),
                    source="TLS Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 "
                        "or TLS 1.3."
                    ),
                )
            )

        if (
            event.sni
            and event.host
            and _normalize_hostname(event.sni)
            != _normalize_hostname(event.host)
        ):
            findings.append(
                ThreatFinding(
                    title="TLS SNI and Host Header Mismatch",
                    severity="medium",
                    description=(
                        f"TLS SNI {event.sni!r} did not match "
                        f"HTTP Host {event.host!r}."
                    ),
                    source="TLS Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review virtual-host configuration and validate "
                        "SNI and Host header handling at the proxy."
                    ),
                )
            )

        if event.server_port == 443 and not event.tls_version:
            findings.append(
                ThreatFinding(
                    title="Missing TLS Metadata on HTTPS Port",
                    severity="medium",
                    description=(
                        "The event used port 443 but did not contain "
                        "a TLS version."
                    ),
                    source="TLS Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Verify TLS termination and ensure security "
                        "telemetry captures TLS protocol details."
                    ),
                )
            )

    return findings