from src.models.threat_finding import ThreatFinding
from src.reporting.timeline_generator import generate_timeline


def test_generate_timeline_returns_list():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        risk_score=160
    )

    timeline = generate_timeline([finding])

    assert isinstance(timeline, list)
    assert len(timeline) == 1


def test_generate_timeline_contains_event_data():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        risk_score=160
    )

    timeline = generate_timeline([finding])

    assert timeline[0]["event"] == "Unknown host with exposed RDP"
    assert timeline[0]["severity"] == "critical"
    assert timeline[0]["ip"] == "192.168.1.77"
    assert timeline[0]["port"] == 3389
    assert timeline[0]["risk_score"] == 160


def test_generate_timeline_contains_time():
    finding = ThreatFinding(
        title="Critical finding",
        severity="critical",
        description="Critical issue.",
        source="test"
    )

    timeline = generate_timeline([finding])

    assert "time" in timeline[0]
    assert timeline[0]["time"] != ""