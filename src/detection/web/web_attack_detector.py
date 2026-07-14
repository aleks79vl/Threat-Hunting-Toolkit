from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


def detect_web_attacks(events: list[SecurityEvent]) -> list[ThreatFinding]:
    findings = []

    admin_401_counter = defaultdict(int)
    not_found_counter = defaultdict(int)

    for event in events:
        raw = event.raw_event.lower()

        if "sqlmap" in raw or "union select" in raw or "' or '1'='1" in raw:
            findings.append(
                ThreatFinding(
                    title="SQL Injection Attempt Detected",
                    severity="critical",
                    description=f"Possible SQL Injection attempt from {event.src_ip}.",
                    source="Web Attack Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation="Review web request and validate input filtering."
                )
            )

        elif "<script>" in raw or "onerror=" in raw:
            findings.append(
                ThreatFinding(
                    title="XSS Attempt Detected",
                    severity="high",
                    description=f"Possible XSS attempt from {event.src_ip}.",
                    source="Web Attack Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation="Review input validation and output encoding."
                )
            )

        elif "../" in raw or "/etc/passwd" in raw:
            findings.append(
                ThreatFinding(
                    title="Directory Traversal Attempt Detected",
                    severity="high",
                    description=f"Possible directory traversal attempt from {event.src_ip}.",
                    source="Web Attack Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation="Verify path traversal protection."
                )
            )

        if "sqlmap" in raw or "nikto" in raw or "curl/" in raw:
            findings.append(
                ThreatFinding(
                    title="Suspicious Web User-Agent Detected",
                    severity="medium",
                    description=f"Suspicious web user-agent detected from {event.src_ip}.",
                    source="Web Attack Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    port=event.dst_port,
                    recommendation="Review automated tool activity and related requests."
                )
            )

        if "/admin/login.php" in raw and " 401 " in raw:
            admin_401_counter[event.src_ip] += 1

        if " 404 " in raw:
            not_found_counter[event.src_ip] += 1

    for ip, count in admin_401_counter.items():
        if count >= 2:
            findings.append(
                ThreatFinding(
                    title="Possible Admin Brute Force Detected",
                    severity="high",
                    description=f"{count} failed admin login attempts detected from {ip}.",
                    source="Web Attack Detector",
                    ip=ip,
                    hostname="web-server",
                    port=80,
                    recommendation="Review admin authentication logs and consider blocking the source IP."
                )
            )

    for ip, count in not_found_counter.items():
        if count >= 3:
            findings.append(
                ThreatFinding(
                    title="Possible Web Enumeration Detected",
                    severity="medium",
                    description=f"{count} HTTP 404 responses detected from {ip}.",
                    source="Web Attack Detector",
                    ip=ip,
                    hostname="web-server",
                    port=80,
                    recommendation="Review requested paths and check for directory scanning."
                )
            )

    return findings