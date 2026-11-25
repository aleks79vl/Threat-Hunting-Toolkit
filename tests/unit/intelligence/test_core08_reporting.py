import json

from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.json_report_generator import (
    generate_json_report,
)
from src.reporting.html_report_generator import (
    generate_html_report,
)


SECRET = "CORE08_SYNTHETIC_SECRET_71fa"


def _ioc(ioc_type, value, confidence="medium", source="CORE-08 Test Feed"):
    return {
        "ioc_type": ioc_type,
        "value": value,
        "confidence": confidence,
        "source": source,
        "description": "Synthetic IOC",
    }


def _finding():
    return ThreatFinding(
        title="CORE-08 Security Observation",
        severity="high",
        description=(
            "Observed evil-example.com, malware-test.net "
            "and request to /shell.php"
        ),
        source="WAF Security Detector",
        ip="198.51.100.10",
        hostname="evil-example.com",
        ioc_match=True,
        ioc_type="domain",
        ioc_value="evil-example.com",
        ioc_confidence="high",
        ioc_source="CORE-08 Test Feed",
        ioc_description="Synthetic IOC",
        ioc_matches=[
            _ioc("domain", "evil-example.com", "high"),
            _ioc("domain", "malware-test.net"),
            _ioc("url", "/shell.php", "low"),
        ],
    )


def _report(finding):
    return ThreatReport(
        title="CORE-08 Security Report",
        generated_at="2026-11-20T12:00:00Z",
        findings=[finding],
        timeline=[],
    )


def test_json_exposes_all_matches_and_keeps_legacy_fields(tmp_path):
    finding = _finding()
    output = tmp_path / "core08.json"

    generate_json_report(_report(finding), str(output))

    data = json.loads(output.read_text(encoding="utf-8"))
    exported = data["findings"][0]

    assert exported["ioc"]["matched"] is True
    assert exported["ioc"]["type"] == "domain"
    assert exported["ioc"]["value"] == "evil-example.com"
    assert exported["ioc"]["confidence"] == "high"

    assert exported["ioc"]["matches"] == finding.ioc_matches


def test_json_top_level_matches_are_serialized_and_redacted(tmp_path):
    finding = _finding()
    finding.ioc_matches.append(
        _ioc(
            "url",
            f"/test?api_key={SECRET}",
        )
    )

    output = tmp_path / "core08_redacted.json"
    generate_json_report(_report(finding), str(output))

    content = output.read_text(encoding="utf-8")
    data = json.loads(content)

    assert SECRET not in content
    assert len(data["findings"][0]["ioc_matches"]) == 4


def test_html_displays_all_ioc_matches(tmp_path):
    output = tmp_path / "core08.html"

    generate_html_report(
        _report(_finding()),
        str(output),
    )

    content = output.read_text(encoding="utf-8")

    assert "IOC Intelligence" in content
    assert "All IOC Matches" in content
    assert "evil-example.com" in content
    assert "malware-test.net" in content
    assert "/shell.php" in content


def test_html_escapes_and_redacts_additional_ioc(tmp_path):
    finding = _finding()

    finding.ioc_matches.append(
        _ioc(
            "url",
            f"/test?api_key={SECRET}",
            source='<svg id="core08-probe" onload="alert(1)">',
        )
    )

    output = tmp_path / "core08_security.html"

    generate_html_report(
        _report(finding),
        str(output),
    )

    content = output.read_text(encoding="utf-8")

    assert SECRET not in content
    assert '<svg id="core08-probe"' not in content
    assert "&lt;svg id=" in content
    assert "core08-probe" in content


def test_legacy_scalar_ioc_still_renders(tmp_path):
    finding = ThreatFinding(
        title="Legacy IOC Observation",
        severity="high",
        description="Legacy IOC",
        source="Unit Test",
        ioc_match=True,
        ioc_type="ip",
        ioc_value="185.220.101.1",
        ioc_confidence="high",
    )

    json_output = tmp_path / "legacy.json"
    html_output = tmp_path / "legacy.html"

    generate_json_report(
        _report(finding),
        str(json_output),
    )
    generate_html_report(
        _report(finding),
        str(html_output),
    )

    data = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    html = html_output.read_text(encoding="utf-8")

    assert data["findings"][0]["ioc"]["value"] == "185.220.101.1"
    assert "185.220.101.1" in html
