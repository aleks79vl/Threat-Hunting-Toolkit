from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


HTTP_2_PROTOCOLS = {
    "HTTP/2",
    "HTTP/2.0",
}


def _normalized_headers(
    headers: dict[str, str],
) -> dict[str, str]:
    return {
        name.lower(): value
        for name, value in headers.items()
    }


def detect_http_protocol_metadata_anomalies(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        protocol = event.protocol.upper()
        headers = _normalized_headers(
            event.request_headers
        )

        if protocol == "HTTP/1.0":
            findings.append(
                ThreatFinding(
                    title="Legacy HTTP/1.0 Request Detected",
                    severity="low",
                    description=(
                        "The request used HTTP/1.0, which may bypass "
                        "assumptions made by modern proxy and security "
                        "controls."
                    ),
                    source="HTTP Protocol Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Disable HTTP/1.0 where possible or ensure it "
                        "is handled consistently across all proxies."
                    ),
                )
            )

        if protocol not in HTTP_2_PROTOCOLS:
            continue

        if "connection" in headers:
            findings.append(
                ThreatFinding(
                    title="HTTP/2 Connection Header Detected",
                    severity="high",
                    description=(
                        "The HTTP/2 request included the forbidden "
                        "hop-by-hop Connection header."
                    ),
                    source="HTTP Protocol Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject HTTP/2 requests containing Connection "
                        "headers before forwarding them upstream."
                    ),
                )
            )

        if "transfer-encoding" in headers:
            findings.append(
                ThreatFinding(
                    title="HTTP/2 Transfer-Encoding Header Detected",
                    severity="high",
                    description=(
                        "The HTTP/2 request included the forbidden "
                        "Transfer-Encoding header."
                    ),
                    source="HTTP Protocol Metadata Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject HTTP/2 requests containing "
                        "Transfer-Encoding and verify protocol "
                        "translation at proxy boundaries."
                    ),
                )
            )

    return findings