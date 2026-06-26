from datetime import datetime

from src.models.threat_finding import ThreatFinding


def generate_timeline(findings: list[ThreatFinding]) -> list[dict]:
    timeline = []

    for finding in findings:
        timeline.append(
            {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": finding.title,
                "severity": finding.severity,
                "ip": finding.ip,
                "port": finding.port,
                "risk_score": finding.risk_score,
                "source": finding.source,
            }
        )

    return timeline
