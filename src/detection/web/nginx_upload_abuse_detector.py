from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


UPLOAD_METHODS = {
    "POST",
    "PUT",
    "PATCH",
}

UPLOAD_PATH_MARKERS = (
    "/upload",
    "/uploads",
    "/file-upload",
    "/attachment",
    "/attachments",
)

EXECUTABLE_EXTENSIONS = (
    ".php",
    ".phtml",
    ".phar",
    ".jsp",
    ".asp",
    ".aspx",
    ".sh",
    ".exe",
)


def _is_upload_path(path: str) -> bool:
    normalized_path = path.lower()

    return any(
        marker in normalized_path
        for marker in UPLOAD_PATH_MARKERS
    )


def _has_executable_extension(path: str) -> bool:
    path_without_query = path.lower().split("?", maxsplit=1)[0]

    return path_without_query.endswith(EXECUTABLE_EXTENSIONS)


def detect_nginx_upload_abuse(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "nginx":
            continue

        if event.method.upper() not in UPLOAD_METHODS:
            continue

        if not _is_upload_path(event.path):
            continue

        if not _has_executable_extension(event.path):
            continue

        findings.append(
            ThreatFinding(
                title="Potential Malicious File Upload Detected",
                severity="high",
                description=(
                    "An upload endpoint received a request targeting "
                    f"an executable file type: {event.path}"
                ),
                source="Nginx Upload Abuse Detector",
                ip=event.client_ip,
                hostname=event.virtual_host or event.host,
                port=event.server_port,
                recommendation=(
                    "Block executable uploads, validate file content "
                    "server-side and store user uploads outside the "
                    "web-accessible directory."
                ),
            )
        )

    return findings