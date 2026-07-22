from urllib.parse import urlparse

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


ADMIN_PATH_PREFIXES = (
    "/admin",
    "/internal",
    "/management",
)


def _is_admin_path(path: str) -> bool:
    normalized_path = urlparse(path).path.rstrip("/")
    segments = [
        segment
        for segment in normalized_path.split("/")
        if segment
    ]

    if not segments:
        return False

    admin_segments = {
        prefix.lstrip("/")
        for prefix in ADMIN_PATH_PREFIXES
    }

    if segments[0] in admin_segments:
        return True

    return (
        len(segments) >= 2
        and segments[0].startswith("v")
        and segments[0][1:].isdigit()
        and segments[1] in admin_segments
    )


def detect_api_admin_endpoint_access(
    events: list[WebInfrastructureEvent],
    *,
    authorized_admin_principals: set[str] | None = None,
) -> list[ThreatFinding]:
    authorized_admin_principals = (
        authorized_admin_principals or set()
    )
    findings = []

    for event in events:
        if event.source != "api_gateway":
            continue

        if not _is_admin_path(event.path):
            continue

        principal_id = event.metadata.get("principal_id", "")

        if event.status_code in {401, 403}:
            findings.append(
                ThreatFinding(
                    title="Unauthorized API Admin Endpoint Access",
                    severity="medium",
                    description=(
                        f"A request to admin endpoint {event.path!r} "
                        f"was denied with HTTP {event.status_code}."
                    ),
                    source="API Admin Endpoint Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review the source IP and principal; restrict "
                        "administrative endpoints to approved users "
                        "and networks."
                    ),
                )
            )
            continue

        if (
            200 <= event.status_code < 300
            and authorized_admin_principals
            and principal_id
            not in authorized_admin_principals
        ):
            findings.append(
                ThreatFinding(
                    title="Unexpected Successful API Admin Access",
                    severity="high",
                    description=(
                        f"Principal {principal_id!r} successfully "
                        f"accessed admin endpoint {event.path!r}, "
                        "but is not in the configured admin allowlist."
                    ),
                    source="API Admin Endpoint Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review role assignments and revoke "
                        "administrative permissions that are not "
                        "explicitly required."
                    ),
                )
            )

    return findings