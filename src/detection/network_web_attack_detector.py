from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


SQLI_PATTERNS = [
    "' or 1=1",
    "\" or 1=1",
    "union select",
    "select * from",
    "drop table",
]

XSS_PATTERNS = [
    "<script>",
    "%3cscript%3e",
    "javascript:",
    "onerror=",
    "onload=",
]

DIRECTORY_TRAVERSAL_PATTERNS = [
    "../",
    "..%2f",
    "%2e%2e%2f",
    "/etc/passwd",
    "boot.ini",
]

ADMIN_PATTERNS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
]

WEB_SHELL_PATTERNS = [
    "/shell.php",
    "/cmd.php",
    "/webshell.php",
    "/upload.php",
]


def detect_network_web_attacks(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    findings = []
    detected = set()

    for event in events:
        uri = event.http_uri or ""
        host = event.http_host or ""

        searchable_text = f"{host} {uri}".lower()

        checks = [
            (
                "SQL Injection Attempt Detected in PCAP",
                "high",
                SQLI_PATTERNS,
                "Possible SQL injection attempt detected in HTTP traffic.",
            ),
            (
                "XSS Attempt Detected in PCAP",
                "high",
                XSS_PATTERNS,
                "Possible cross-site scripting attempt detected in HTTP traffic.",
            ),
            (
                "Directory Traversal Attempt Detected in PCAP",
                "high",
                DIRECTORY_TRAVERSAL_PATTERNS,
                "Possible directory traversal attempt detected in HTTP traffic.",
            ),
            (
                "Admin Panel Enumeration Detected in PCAP",
                "medium",
                ADMIN_PATTERNS,
                "Possible admin panel enumeration detected in HTTP traffic.",
            ),
            (
                "Suspicious Web Shell URI Detected in PCAP",
                "critical",
                WEB_SHELL_PATTERNS,
                "Possible web shell related URI detected in HTTP traffic.",
            ),
        ]

        for title, severity, patterns, description in checks:
            if any(pattern in searchable_text for pattern in patterns):
                detection_key = (
                    title,
                    event.src_ip,
                    event.dst_ip,
                    event.http_host,
                    event.http_uri,
                )

                if detection_key in detected:
                    continue

                detected.add(detection_key)

                findings.append(
                    ThreatFinding(
                        title=title,
                        severity=severity,
                        description=description,
                        source="PCAP Network Detection",
                        ip=event.dst_ip or event.src_ip,
                        port=event.dst_port,
                        recommendation=(
                            "Investigate the HTTP request and verify whether "
                            "it represents malicious web activity."
                        ),
                    )
                )

    return findings