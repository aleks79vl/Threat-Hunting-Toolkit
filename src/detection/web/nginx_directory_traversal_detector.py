from urllib.parse import unquote

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def _decode_path(path: str) -> str:
    decoded_path = path

    for _ in range(2):
        new_path = unquote(decoded_path)

        if new_path == decoded_path:
            break

        decoded_path = new_path

    return decoded_path


def detect_nginx_directory_traversal(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "nginx":
            continue

        normalized_path = _decode_path(event.path)

        if "../" not in normalized_path and "..\\" not in normalized_path:
            continue

        findings.append(
            ThreatFinding(
                title="Nginx Directory Traversal Attempt Detected",
                severity="high",
                description=(
                    "A request contained a directory traversal pattern: "
                    f"{event.path}"
                ),
                source="Nginx Directory Traversal Detector",
                ip=event.client_ip,
                hostname=event.virtual_host or event.host,
                port=event.server_port,
                recommendation=(
                    "Review request filtering and ensure the application "
                    "does not resolve user-controlled paths."
                ),
            )
        )

    return findings