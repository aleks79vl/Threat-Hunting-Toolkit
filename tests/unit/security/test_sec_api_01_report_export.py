import json

import pytest

from src.detection.web.load_balancer_rate_limit_detector import (
    detect_rate_limit_bypass,
)
from src.models.threat_report import ThreatReport
from src.parsers.api_gateway_log_parser import parse_api_gateway_log
from src.reporting.html_report_generator import generate_html_report
from src.reporting.json_report_generator import generate_json_report


SYNTHETIC_SECRET = "SEC_API_01_SYNTHETIC_NOT_REAL_9f72"


@pytest.mark.parametrize("report_format", ["json", "html"])
def test_api_key_secret_is_not_written_to_report(
    tmp_path,
    report_format,
):
    records = [
        {
            "timestamp": "2026-11-17T06:00:00Z",
            "client_ip": f"198.51.100.{number}",
            "http_method": "GET",
            "path": "/test",
            "status": 200,
            "api_key_id": SYNTHETIC_SECRET,
            "request_headers": {
                "X-API-Key": SYNTHETIC_SECRET,
            },
        }
        for number in (1, 2, 3)
    ]

    input_path = tmp_path / "api_gateway.jsonl"
    input_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(input_path))

    assert len(events) == 3
    assert all(
        event.request_headers["X-API-Key"] == "[REDACTED]"
        for event in events
    )

    findings = detect_rate_limit_bypass(events)

    assert len(findings) == 1
    assert findings[0].source == "Load Balancer Rate Limit Detector"

    report = ThreatReport(
        title="SEC-API-01 Synthetic Security Test",
        generated_at="2026-11-17T06:00:00Z",
        findings=findings,
        timeline=[],
    )

    output_path = tmp_path / f"security_report.{report_format}"

    if report_format == "json":
        generate_json_report(report, str(output_path))
    else:
        generate_html_report(report, str(output_path))

    content = output_path.read_text(encoding="utf-8")

    assert SYNTHETIC_SECRET not in content
    assert "api_key:[REDACTED]" in content
