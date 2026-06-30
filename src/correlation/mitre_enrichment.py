from src.models.threat_finding import ThreatFinding
from src.correlation.mitre_mapper import get_mitre_mapping


def enrich_finding_with_mitre(finding: ThreatFinding) -> ThreatFinding:
    mitre = get_mitre_mapping(finding.title)

    finding.technique = mitre["technique"]
    finding.technique_name = mitre["name"]
    finding.tactic = mitre["tactic"]

    return finding