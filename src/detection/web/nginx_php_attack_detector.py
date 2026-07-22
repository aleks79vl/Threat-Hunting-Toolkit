from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


PHP_SOURCE_DISCLOSURE_SUFFIXES = (
    ".phps",
    ".php~",
    ".php.bak",
    ".php.old",
    ".php.save",
)

DANGEROUS_PHP_QUERY_MARKERS = (
    "auto_prepend_file=",
    "allow_url_include=",
    "php://input",
)


def _path_without_query(path: str) -> str:
    return path.lower().split("?", maxsplit=1)[0]


def detect_nginx_php_attacks(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "nginx":
            continue

        path_without_query = _path_without_query(event.path)
        normalized_path = event.path.lower()

        if path_without_query.endswith(
            PHP_SOURCE_DISCLOSURE_SUFFIXES
        ):
            findings.append(
                ThreatFinding(
                    title="Potential PHP Source Disclosure Attempt",
                    severity="high",
                    description=(
                        "A request targeted a PHP source or backup file: "
                        f"{event.path}"
                    ),
                    source="Nginx PHP Attack Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Block access to backup and source files, and "
                        "review Nginx location rules."
                    ),
                )
            )
            continue

        if any(
            marker in normalized_path
            for marker in DANGEROUS_PHP_QUERY_MARKERS
        ):
            findings.append(
                ThreatFinding(
                    title="Potential PHP Runtime Abuse Attempt",
                    severity="high",
                    description=(
                        "A request contained a suspicious PHP runtime "
                        f"parameter: {event.path}"
                    ),
                    source="Nginx PHP Attack Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review PHP-FPM configuration, validate request "
                        "parameters and investigate related process "
                        "activity."
                    ),
                )
            )

    return findings