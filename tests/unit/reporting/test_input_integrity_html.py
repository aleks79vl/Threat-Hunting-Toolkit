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

