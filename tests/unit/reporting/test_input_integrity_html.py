"""Security tests for HTML Input Integrity reporting."""

from html import escape

import pytest

from src.models.threat_report import ThreatReport
from src.reporting.html_report_generator import (
    _generate_input_integrity_section,
)


def make_report(input_integrity):
    return ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-11-10 00:00:00",
        input_integrity=input_integrity,
    )


@pytest.mark.parametrize(
    "input_integrity",
    [None, {}],
    ids=["missing_integrity", "empty_integrity"],
)
def test_input_integrity_section_absent_without_metadata(
    input_integrity,
):
    report = make_report(input_integrity)

    assert _generate_input_integrity_section(report) == ""


def test_input_integrity_section_displays_failed_sources():
    report = make_report({
        "status": "incomplete",
        "source_failures": [
            {
                "source": "windows_events",
                "reason": "file_not_found",
            },
            {
                "source": "waf_cdn",
                "reason": "permission_denied",
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert "Input Integrity" in html
    assert "Incomplete" in html
    assert "windows_events" in html
    assert "file_not_found" in html
    assert "waf_cdn" in html
    assert "permission_denied" in html


def test_input_integrity_section_escapes_html_injection():
    malicious_source = '<script>alert("x")</script>'
    malicious_reason = '<img src=x onerror=alert(1)>'

    report = make_report({
        "status": "incomplete",
        "source_failures": [
            {
                "source": malicious_source,
                "reason": malicious_reason,
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert escape(malicious_source) in html
    assert escape(malicious_reason) in html

    assert malicious_source not in html
    assert malicious_reason not in html
    assert "<script" not in html
    assert "<img" not in html


def test_input_integrity_section_ignores_sensitive_extra_fields():
    report = make_report({
        "status": "incomplete",
        "source_failures": [
            {
                "source": "nginx",
                "reason": "file_not_found",
                "path": "/private/secret-path.log",
                "exception": "sensitive_exception_message",
                "raw_event": "sensitive_raw_log_content",
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert "nginx" in html
    assert "file_not_found" in html

    assert "/private/secret-path.log" not in html
    assert "sensitive_exception_message" not in html
    assert "sensitive_raw_log_content" not in html


def test_input_integrity_section_handles_missing_failure_details():
    report = make_report({
        "status": "incomplete",
        "source_failures": [],
    })

    html = _generate_input_integrity_section(report)

    assert "Input Integrity" in html
    assert "Incomplete" in html
    assert (
        "Incomplete telemetry; no source failure details"
        in html
    )


def test_input_integrity_html_shows_partial_parser_without_false_unavailable_source():
    report = make_report({
        "status": "incomplete",
        "source_failures": [],
        "parser_diagnostics": [
            {
                "source": "firewall",
                "read": 4,
                "accepted": 2,
                "rejected": 2,
                "reason_codes": [
                    "invalid_record",
                    "malformed_row",
                ],
                "issues_dropped": 1,
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert "Input Integrity" in html
    assert "Parser Diagnostics" in html
    assert "firewall" in html
    assert "invalid_record" in html
    assert "malformed_row" in html

    assert "<td>4</td>" in html
    assert "<td>2</td>" in html
    assert "<td>1</td>" in html

    assert "Unavailable Sources" not in html
    assert (
        "Incomplete telemetry; no source failure details"
        not in html
    )


def test_input_integrity_html_combines_source_failure_and_parser_rejection():
    report = make_report({
        "status": "incomplete",
        "source_failures": [
            {
                "source": "windows_events",
                "reason": "file_not_found",
            },
        ],
        "parser_diagnostics": [
            {
                "source": "nginx",
                "read": 3,
                "accepted": 2,
                "rejected": 1,
                "reason_codes": ["invalid_json"],
                "issues_dropped": 0,
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert "Unavailable Sources" in html
    assert "windows_events" in html
    assert "file_not_found" in html

    assert "Parser Diagnostics" in html
    assert "nginx" in html
    assert "invalid_json" in html


def test_input_integrity_html_escapes_parser_diagnostics():
    malicious_source = '<script>alert("x")</script>'
    malicious_reason = '<img src=x onerror=alert(1)>'

    report = make_report({
        "status": "incomplete",
        "source_failures": [],
        "parser_diagnostics": [
            {
                "source": malicious_source,
                "read": 1,
                "accepted": 0,
                "rejected": 1,
                "reason_codes": [malicious_reason],
                "issues_dropped": 0,
                "raw_event": "PRIVATE_RAW_TELEMETRY",
                "path": "/private/internal/secret.log",
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert escape(malicious_source) in html
    assert escape(malicious_reason) in html

    assert malicious_source not in html
    assert malicious_reason not in html

    assert "<script" not in html
    assert "<img" not in html
    assert "PRIVATE_RAW_TELEMETRY" not in html
    assert "/private/internal/secret.log" not in html


def test_input_integrity_html_handles_zero_retained_issues():
    report = make_report({
        "status": "incomplete",
        "source_failures": [],
        "parser_diagnostics": [
            {
                "source": "firewall",
                "read": 3,
                "accepted": 1,
                "rejected": 2,
                "reason_codes": [],
                "issues_dropped": 2,
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    expected_row = (
        "<tr>"
        "<td>firewall</td>"
        "<td>3</td>"
        "<td>1</td>"
        "<td>2</td>"
        "<td>Not available</td>"
        "<td>2</td>"
        "<td>Not enabled</td>"
        "<td>Not enabled</td>"
        "</tr>"
    )

    assert expected_row in html
    assert "Parser Diagnostics" in html
    assert "Unavailable Sources" not in html
    assert "Reason codes describe retained" in html


def test_input_integrity_html_displays_safe_quarantine_metrics():
    secret = "PRIVATE_QUARANTINE_RAW_DO_NOT_EXPORT"

    report = make_report({
        "status": "incomplete",
        "source_failures": [],
        "parser_diagnostics": [
            {
                "source": "firewall",
                "read": 115,
                "accepted": 10,
                "rejected": 105,
                "reason_codes": ["too_few_fields"],
                "issues_dropped": 5,
                "quarantine": {
                    "retained": 100,
                    "dropped": 5,
                    "raw_record": secret,
                },
            },
            {
                "source": "nginx",
                "read": 3,
                "accepted": 2,
                "rejected": 1,
                "reason_codes": ["invalid_json"],
                "issues_dropped": 0,
            },
        ],
    })

    html = _generate_input_integrity_section(report)

    assert "Input Integrity" in html
    assert "Parser Diagnostics" in html

    assert "Quarantine Retained" in html
    assert "Quarantine Dropped" in html

    expected_firewall_row = (
        "<tr>"
        "<td>firewall</td>"
        "<td>115</td>"
        "<td>10</td>"
        "<td>105</td>"
        "<td>too_few_fields</td>"
        "<td>5</td>"
        "<td>100</td>"
        "<td>5</td>"
        "</tr>"
    )

    assert expected_firewall_row in html

    expected_nginx_row = (
        "<tr>"
        "<td>nginx</td>"
        "<td>3</td>"
        "<td>2</td>"
        "<td>1</td>"
        "<td>invalid_json</td>"
        "<td>0</td>"
        "<td>Not enabled</td>"
        "<td>Not enabled</td>"
        "</tr>"
    )

    assert expected_nginx_row in html

    assert secret not in html
    assert "raw_record" not in html
