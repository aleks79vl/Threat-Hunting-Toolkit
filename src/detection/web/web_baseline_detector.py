import json
from urllib.parse import urlparse

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def load_web_security_baseline(
    file_path: str,
) -> dict:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def detect_web_baseline_deviations(
    events: list[WebInfrastructureEvent],
    baseline: dict,
) -> list[ThreatFinding]:
    allowed_tls_versions = {
        version.lower()
        for version in baseline.get(
            "allowed_tls_versions",
            [],
        )
    }

    allowed_websocket_paths = set(
        baseline.get("allowed_websocket_paths", [])
    )

    suspicious_user_agent_markers = {
        marker.lower()
        for marker in baseline.get(
            "suspicious_user_agent_markers",
            [],
        )
    }

    findings = []

    for event in events:
        normalized_user_agent = event.user_agent.lower()
        matching_markers = [
            marker
            for marker in suspicious_user_agent_markers
            if marker in normalized_user_agent
        ]

        if matching_markers:
            findings.append(
                ThreatFinding(
                    title=(
                        "Threat Intelligence User-Agent Match "
                        "in Web Activity"
                    ),
                    severity="medium",
                    description=(
                        "The request User-Agent matched suspicious "
                        f"baseline marker(s): "
                        f"{', '.join(sorted(matching_markers))}."
                    ),
                    source="Web Baseline Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review the request for scanning activity and "
                        "apply appropriate WAF or rate-limit controls."
                    ),
                )
            )

        if (
            event.tls_version
            and allowed_tls_versions
            and event.tls_version.lower()
            not in allowed_tls_versions
        ):
            findings.append(
                ThreatFinding(
                    title="TLS Version Deviates from Web Baseline",
                    severity="medium",
                    description=(
                        f"Observed TLS version {event.tls_version!r} "
                        "is not listed in the allowed web baseline."
                    ),
                    source="Web Baseline Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review TLS configuration and update the "
                        "baseline only after a security review."
                    ),
                )
            )

        path = urlparse(event.path).path

        if (
            event.websocket_upgrade
            and allowed_websocket_paths
            and path not in allowed_websocket_paths
        ):
            findings.append(
                ThreatFinding(
                    title=(
                        "WebSocket Path Deviates from "
                        "Web Baseline"
                    ),
                    severity="medium",
                    description=(
                        f"WebSocket upgrade was observed for "
                        f"unapproved path {path!r}."
                    ),
                    source="Web Baseline Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Verify whether the WebSocket endpoint is "
                        "authorized before adding it to the baseline."
                    ),
                )
            )

    return findings