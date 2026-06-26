import json

from src.models.threat_finding import ThreatFinding


def test_threat_finding_creation():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes Remote Desktop service.",
        source="correlation",
        ip="192.168.1.77",
        hostname="unknown-host",
        port=3389,
        technique="T1021",
        recommendation="Investigate host and restrict RDP access."
    )

    assert finding.title == "Unknown host with exposed RDP"
    assert finding.severity == "critical"
    assert finding.ip == "192.168.1.77"
    assert finding.port == 3389


def test_threat_finding_to_dict():
    finding = ThreatFinding(
        title="Critical port exposed",
        severity="high",
        description="Host exposes SSH service.",
        source="nmap",
        ip="192.168.1.10",
        port=22
    )

    data = finding.to_dict()

    assert isinstance(data, dict)
    assert data["title"] == "Critical port exposed"
    assert data["severity"] == "high"
    assert data["port"] == 22


def test_threat_finding_to_json():
    finding = ThreatFinding(
        title="Unknown host",
        severity="high",
        description="Host is not listed in asset inventory.",
        source="unknown_ip_detector",
        ip="192.168.1.77"
    )

    parsed = json.loads(finding.to_json())

    assert parsed["title"] == "Unknown host"
    assert parsed["severity"] == "high"
    assert parsed["ip"] == "192.168.1.77"