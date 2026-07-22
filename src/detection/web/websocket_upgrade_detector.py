from urllib.parse import urlparse

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def _normalized_path(path: str) -> str:
    return urlparse(path).path


def detect_websocket_upgrade_anomalies(
    events: list[WebInfrastructureEvent],
    *,
    allowed_websocket_paths: set[str] | None = None,
) -> list[ThreatFinding]:
    findings = []
    allowed_paths = allowed_websocket_paths or set()

    for event in events:
        path = _normalized_path(event.path)

        if (
            event.websocket_upgrade
            and allowed_websocket_paths is not None
            and path not in allowed_paths
        ):
            findings.append(
                ThreatFinding(
                    title="Unexpected WebSocket Upgrade Path",
                    severity="medium",
                    description=(
                        f"WebSocket upgrade was requested for "
                        f"non-approved path {path!r}."
                    ),
                    source="WebSocket Upgrade Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Restrict WebSocket upgrades to explicitly "
                        "approved paths at the proxy or WAF layer."
                    ),
                )
            )

        if event.status_code == 101 and not event.websocket_upgrade:
            findings.append(
                ThreatFinding(
                    title="Unexpected HTTP Protocol Switch",
                    severity="medium",
                    description=(
                        "The server returned HTTP 101 Switching "
                        "Protocols without a WebSocket upgrade event."
                    ),
                    source="WebSocket Upgrade Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Verify protocol-upgrade handling and ensure "
                        "only expected upgrade mechanisms are allowed."
                    ),
                )
            )

        if event.websocket_upgrade and event.server_port == 80:
            findings.append(
                ThreatFinding(
                    title="WebSocket Upgrade Without TLS",
                    severity="high",
                    description=(
                        "A WebSocket upgrade was observed on HTTP "
                        "port 80 instead of a TLS-protected endpoint."
                    ),
                    source="WebSocket Upgrade Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Require secure WebSocket connections over "
                        "WSS and redirect HTTP traffic to HTTPS."
                    ),
                )
            )

    return findings