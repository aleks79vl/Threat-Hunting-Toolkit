import ipaddress
import re

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


BACKEND_EXPOSURE_HEADERS = frozenset(
    {
        "location",
        "content-location",
        "x-backend",
        "x-backend-server",
        "x-upstream",
        "x-upstream-addr",
    }
)

IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def _contains_private_ip(value: str) -> bool:
    for candidate in IP_ADDRESS_PATTERN.findall(value):
        try:
            if ipaddress.ip_address(candidate).is_private:
                return True
        except ValueError:
            continue

    return False


def detect_backend_exposure(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        for name, value in event.response_headers.items():
            if name.lower() not in BACKEND_EXPOSURE_HEADERS:
                continue

            if not _contains_private_ip(value):
                continue

            findings.append(
                ThreatFinding(
                    title="Private Backend Address Exposed in Response",
                    severity="high",
                    description=(
                        "The response header "
                        f"{name!r} exposed a private backend address: "
                        f"{value!r}."
                    ),
                    source="Backend Exposure Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Remove internal backend addresses from response "
                        "headers and rewrite redirects at the reverse "
                        "proxy boundary."
                    ),
                )
            )

    return findings