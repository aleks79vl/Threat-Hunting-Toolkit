import ipaddress

from src.detection.web.reverse_proxy_policy import ReverseProxyPolicy

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def detect_nginx_reverse_proxy_abuse(
    events: list[WebInfrastructureEvent],
    *,
    policy: ReverseProxyPolicy | None = None,
) -> list[ThreatFinding]:
    policy = policy or ReverseProxyPolicy()
    findings = []

    for event in events:
        if event.source != "nginx":
            continue

        if _is_private_ip(event.host):
            findings.append(
                ThreatFinding(
                    title="Potential Backend Exposure Through Host Header",
                    severity="high",
                    description=(
                        "A request used a private IP address in the "
                        f"Host header: {event.host}"
                    ),
                    source="Nginx Reverse Proxy Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host,
                    port=event.server_port,
                    recommendation=(
                        "Restrict accepted Host headers and verify that "
                        "private backend addresses are not externally "
                        "reachable through the reverse proxy."
                    ),
                )
            )

        if (
            event.forwarded_for
            and not policy.is_trusted_proxy(event.client_ip)
        ):
            findings.append(
                ThreatFinding(
                    title="Untrusted X-Forwarded-For Header Detected",
                    severity="medium",
                    description=(
                        "A client not listed as a trusted proxy supplied "
                        "an X-Forwarded-For chain."
                    ),
                    source="Nginx Reverse Proxy Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Configure trusted proxy IP addresses and discard "
                        "forwarded headers from untrusted clients."
                    ),
                )
            )

    return findings