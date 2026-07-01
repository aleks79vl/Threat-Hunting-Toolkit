from collections import Counter

from src.models.threat_finding import ThreatFinding


def generate_mitre_statistics(
    findings: list[ThreatFinding]
) -> dict:
    tactics = Counter()
    techniques = Counter()

    for finding in findings:
        tactic = finding.tactic or "Unknown"
        technique = finding.technique or "Unknown"

        tactics[tactic] += 1
        techniques[technique] += 1

    return {
        "tactics": dict(tactics),
        "techniques": dict(techniques),
    }