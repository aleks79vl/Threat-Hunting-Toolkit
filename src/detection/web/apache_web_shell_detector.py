import re

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


SUSPICIOUS_WEB_SHELL_PATH = re.compile(
    r"/(?:uploads?|images?|cache|tmp|backup|assets)/"
    r"[^/?]+\.(?:php|phtml|php\d|phar)(?:\?|$)",
    re.IGNORECASE,
)

SUSPICIOUS_WEB_SHELL_NAME = re.compile(
    r"/(?:cmd|shell|wso|c99|r57|b374k|webshell)"
    r"\.(?:php|phtml|php\d|phar)(?:\?|$)",
    re.IGNORECASE,
)

SUSPICIOUS_COMMAND_PARAMETER = re.compile(
    r"[?&](?:cmd|command|exec|system|shell|passthru)=",
    re.IGNORECASE,
)


def detect_apache_web_shells(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "apache":
            continue

        is_suspicious_path = (
            SUSPICIOUS_WEB_SHELL_PATH.search(event.path)
            or SUSPICIOUS_WEB_SHELL_NAME.search(event.path)
        )

        if is_suspicious_path:
            findings.append(
                ThreatFinding(
                    title="Potential Apache Web Shell Access",
                    severity="high",
                    description=(
                        "A request targeted a script in a suspicious "
                        f"web-accessible path: {event.path}"
                    ),
                    source="Apache Web Shell Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Investigate the script, review recent file "
                        "changes, and isolate the affected web host "
                        "if unauthorized code is confirmed."
                    ),
                )
            )
            continue

        if SUSPICIOUS_COMMAND_PARAMETER.search(event.path):
            findings.append(
                ThreatFinding(
                    title="Potential Web Shell Command Execution",
                    severity="critical",
                    description=(
                        "A request contained a parameter commonly "
                        f"associated with command execution: {event.path}"
                    ),
                    source="Apache Web Shell Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Review the requested endpoint and server "
                        "process activity for possible web shell use."
                    ),
                )
            )

    return findings