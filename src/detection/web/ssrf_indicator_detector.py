import ipaddress
from urllib.parse import parse_qsl, urlparse

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


SSRF_PARAMETER_NAMES = frozenset(
    {
        "url",
        "uri",
        "target",
        "redirect",
        "callback",
        "webhook",
        "image",
    }
)


def _is_internal_target(value: str) -> bool:
    parsed = urlparse(value)

    if not parsed.hostname:
        return False

    hostname = parsed.hostname.lower()

    if hostname in {"localhost", "localhost.localdomain"}:
        return True

    if hostname.endswith(".internal") or hostname.endswith(".local"):
        return True

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
    )


def detect_ssrf_indicators(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        query_string = urlparse(event.path).query

        for parameter, value in parse_qsl(
            query_string,
            keep_blank_values=True,
        ):
            if parameter.lower() not in SSRF_PARAMETER_NAMES:
                continue

            if not _is_internal_target(value):
                continue

            findings.append(
                ThreatFinding(
                    title="Potential SSRF Request to Internal Target",
                    severity="high",
                    description=(
                        f"The query parameter {parameter!r} contained "
                        f"an internal URL target: {value!r}."
                    ),
                    source="SSRF Indicator Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Allow outbound requests only to approved "
                        "destinations and block private, loopback, and "
                        "link-local address ranges."
                    ),
                )
            )

    return findings