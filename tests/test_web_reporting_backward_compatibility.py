import json

from src.models.threat_report import ThreatReport
from src.reporting.html_report_generator import (
    generate_html_report,
)
from src.reporting.json_report_generator import (
    generate_json_report,
)


def test_reports_support_threat_report_without_web_telemetry(
    tmp_path,
):
    report = ThreatReport(
        title="Legacy Threat Hunting Report",
        generated_at="2026-07-22 23:10:00",
    )

    json_output = tmp_path / "legacy_report.json"
    html_output = tmp_path / "legacy_report.html"

    generate_json_report(report, str(json_output))
    generate_html_report(report, str(html_output))

    json_data = json.loads(
        json_output.read_text(encoding="utf-8")
    )
    html_content = html_output.read_text(encoding="utf-8")

    assert json_data["web_infrastructure_statistics"] == {}
    assert "Web Infrastructure Telemetry" in html_content
    assert (
        "No web infrastructure telemetry available"
        in html_content
    )