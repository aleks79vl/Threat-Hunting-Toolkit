from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


ROUTE_OVERRIDE_HEADERS = frozenset(
    {
        "x-original-url",
        "x-rewrite-url",
    }
)


def detect_header_manipulation(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        normalized_headers = {
            name.lower(): value
            for name, value in event.request_headers.items()
        }

        for header_name in ROUTE_OVERRIDE_HEADERS:
            value = normalized_headers.get(header_name)

            if not value:
                continue

            findings.append(
                ThreatFinding(
                    title="Potential Header-Based Route Override",
                    severity="medium",
                    description=(
                        f"The request supplied {header_name!r} with "
                        f"the route value {value!r}."
                    ),
                    source="Header Manipulation Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Remove route-override headers from untrusted "
                        "requests at the reverse proxy boundary."
                    ),
                )
            )

        method_override = normalized_headers.get(
            "x-http-method-override"
        )

        if (
            method_override
            and method_override.upper() != event.method.upper()
        ):
            findings.append(
                ThreatFinding(
                    title="HTTP Method Override Header Detected",
                    severity="medium",
                    description=(
                        "The request method "
                        f"{event.method!r} was accompanied by an "
                        "X-HTTP-Method-Override value of "
                        f"{method_override!r}."
                    ),
                    source="Header Manipulation Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject HTTP method override headers unless "
                        "they are explicitly required and validated."
                    ),
                )
            )

        for name, value in event.request_headers.items():
            if "\r" not in value and "\n" not in value:
                continue

            findings.append(
                ThreatFinding(
                    title="Potential Header Injection Detected",
                    severity="high",
                    description=(
                        f"The request header {name!r} contains a "
                        "carriage return or newline character."
                    ),
                    source="Header Manipulation Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject control characters in inbound HTTP "
                        "header values before forwarding requests."
                    ),
                )
            )

    return findings