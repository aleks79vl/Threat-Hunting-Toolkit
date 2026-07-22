from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


HIGH_RISK_METHODS = {
    "CONNECT",
    "TRACE",
}

MODIFICATION_METHODS = {
    "DELETE",
    "PATCH",
    "PUT",
}

STANDARD_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
}


def detect_nginx_http_method_abuse(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "nginx":
            continue

        method = event.method.upper()

        if method in HIGH_RISK_METHODS:
            severity = "high"
            title = "High-Risk HTTP Method Detected"
        elif method in MODIFICATION_METHODS:
            severity = "medium"
            title = "Potential HTTP Method Abuse Detected"
        elif method not in STANDARD_METHODS:
            severity = "medium"
            title = "Unexpected HTTP Method Detected"
        else:
            continue

        findings.append(
            ThreatFinding(
                title=title,
                severity=severity,
                description=(
                    f"HTTP method {method} was requested for "
                    f"{event.path}."
                ),
                source="Nginx HTTP Method Detector",
                ip=event.client_ip,
                hostname=event.virtual_host or event.host,
                port=event.server_port,
                recommendation=(
                    "Validate the allowed HTTP methods for this "
                    "endpoint and restrict unnecessary methods."
                ),
            )
        )

    return findings