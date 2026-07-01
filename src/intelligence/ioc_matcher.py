from src.intelligence.ioc_loader import get_iocs
from src.models.threat_finding import ThreatFinding


def match_ioc(finding: ThreatFinding):
    """
    Return matching IOC if found.
    """

    for ioc in get_iocs():
        if ioc.ioc_type == "ip" and ioc.value == finding.ip:
            return ioc

    return None


def enrich_finding_with_ioc(finding: ThreatFinding) -> ThreatFinding:
    """
    Enrich ThreatFinding with IOC metadata if match is found.
    """

    ioc = match_ioc(finding)

    if ioc is None:
        return finding

    finding.ioc_match = True
    finding.ioc_type = ioc.ioc_type
    finding.ioc_value = ioc.value
    finding.ioc_confidence = ioc.confidence
    finding.ioc_source = ioc.source
    finding.ioc_description = ioc.description

    return finding