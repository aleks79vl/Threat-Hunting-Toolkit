import ipaddress

from src.detection.web.reverse_proxy_policy import ReverseProxyPolicy
from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_proxy_chain_anomalies(
    events: list[WebInfrastructureEvent],
    *,
    policy: ReverseProxyPolicy,
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if not event.forwarded_for:
            continue

        if not policy.is_trusted_proxy(event.client_ip):
            continue

        if len(event.forwarded_for) > policy.max_proxy_chain_length:
            findings.append(
                ThreatFinding(
                    title="Excessive Reverse Proxy Chain Length",
                    severity="medium",
                    description=(
                        "A trusted proxy supplied an X-Forwarded-For "
                        f"chain with {len(event.forwarded_for)} addresses; "
                        "the configured maximum was "
                        f"{policy.max_proxy_chain_length}."
                    ),
                    source="Reverse Proxy Chain Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Limit proxy-chain length and verify the "
                        "forwarding configuration of each trusted proxy."
                    ),
                )
            )

        for address in event.forwarded_for:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                findings.append(
                    ThreatFinding(
                        title="Invalid Address in X-Forwarded-For Chain",
                        severity="medium",
                        description=(
                            "A trusted proxy supplied a non-IP value in "
                            f"the X-Forwarded-For chain: {address!r}."
                        ),
                        source="Reverse Proxy Chain Detector",
                        ip=event.client_ip,
                        hostname=event.virtual_host or event.host,
                        port=event.server_port,
                        recommendation=(
                            "Validate forwarded-address headers at the "
                            "trusted proxy boundary."
                        ),
                    )
                )

    return findings