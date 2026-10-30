from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


SQLI_PATTERNS = [
    "' or 1=1",
    '" or 1=1',
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

    findings: list[ThreatFinding] = []

    # Each detection key maps to:
    # (finding, (earliest_timestamp, latest_timestamp))
    #
    # A None time range means at least one matching
    # packet has an invalid or missing timestamp.
    detected = {}

    for event in events:
        packet_time = normalize_packet_time(event.timestamp)

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
            if not any(
                pattern in searchable_text
                for pattern in patterns
            ):
                continue

            detection_key = (
                title,
                event.src_ip,
                event.dst_ip,
                event.http_host,
                event.http_uri,
            )

            if detection_key in detected:
                finding, time_range = detected[detection_key]

                if time_range is None or packet_time is None:
                    detected[detection_key] = (
                        finding,
                        None,
                    )
                else:
                    earliest, latest = time_range

                    if packet_time[0] < earliest[0]:
                        earliest = packet_time

                    if packet_time[0] > latest[0]:
                        latest = packet_time

                    detected[detection_key] = (
                        finding,
                        (earliest, latest),
                    )

                continue

            finding = ThreatFinding(
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

            findings.append(finding)

            detected[detection_key] = (
                finding,
                (
                    (packet_time, packet_time)
                    if packet_time is not None
                    else None
                ),
            )

    for finding, time_range in detected.values():
        if time_range is None:
            finding.first_seen = None
            finding.last_seen = None
        else:
            finding.first_seen = time_range[0][1]
            finding.last_seen = time_range[1][1]

    return findings