import json

from dataclasses import replace

from src.main import main

from src.config.app_config import default_app_config


def test_application_generates_json_and_html_reports(tmp_path):
    json_output_file = tmp_path / "threat_report.json"
    html_output_file = tmp_path / "threat_report.html"

    config = replace(
        default_app_config(),
        json_output_file=str(json_output_file),
        html_output_file=str(html_output_file),
    )

    main(config)

    assert json_output_file.is_file()
    assert html_output_file.is_file()

    with json_output_file.open(encoding="utf-8") as report_file:
        json_report = json.load(report_file)

    assert isinstance(json_report, dict)
    assert json_report

    html_report = html_output_file.read_text(encoding="utf-8")

    assert json_report
    assert "Threat Hunting Report" in html_report
    assert "network_statistics" in json_report
    assert "linux_statistics" in json_report
    assert "web_infrastructure_statistics" in json_report