"""CORE-07 input integrity contract tests."""

from src.application.input_integrity import (
    build_input_integrity,
)
from src.application.source_failure import SourceFailure

from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.quarantine_buffer import QuarantineBuffer


def test_input_integrity_does_not_claim_complete():
    diagnostics = ParserDiagnostics(source="nginx")
    diagnostics.accept()

    result = build_input_integrity(
        source_failures=[],
        parser_diagnostics=[diagnostics],
    )

    assert result is None


def test_input_integrity_reports_partial_parser_input():
    diagnostics = ParserDiagnostics(
        source="nginx",
        max_issues=1,
    )

    diagnostics.accept()
    diagnostics.reject(2, "invalid_json")
    diagnostics.reject(3, "invalid_structure")

    result = build_input_integrity(
        source_failures=[],
        parser_diagnostics=[diagnostics],
    )

    assert result == {
        "status": "incomplete",
        "source_failures": [],
        "parser_diagnostics": [
            {
                "source": "nginx",
                "read": 3,
                "accepted": 1,
                "rejected": 2,
                "reason_codes": ["invalid_json"],
                "issues_dropped": 1,
            },
        ],
    }


def test_input_integrity_reports_unavailable_source():
    result = build_input_integrity(
        source_failures=[
            SourceFailure(
                source="windows_events",
                reason="file_not_found",
            ),
        ],
        parser_diagnostics=[],
    )

    assert result == {
        "status": "incomplete",
        "source_failures": [
            {
                "source": "windows_events",
                "reason": "file_not_found",
            },
        ],
        "parser_diagnostics": [],
    }


def test_input_integrity_combines_independent_failures():
    diagnostics = ParserDiagnostics(source="firewall")
    diagnostics.accept()
    diagnostics.reject(2, "malformed_record")

    result = build_input_integrity(
        source_failures=[
            SourceFailure(
                source="waf_cdn",
                reason="permission_denied",
            ),
        ],
        parser_diagnostics=[diagnostics],
    )

    assert result == {
        "status": "incomplete",
        "source_failures": [
            {
                "source": "waf_cdn",
                "reason": "permission_denied",
            },
        ],
        "parser_diagnostics": [
            {
                "source": "firewall",
                "read": 2,
                "accepted": 1,
                "rejected": 1,
                "reason_codes": ["malformed_record"],
                "issues_dropped": 0,
            },
        ],
    }


def test_input_integrity_preserves_rejections_with_zero_issue_limit():
    diagnostics = ParserDiagnostics(
        source="firewall",
        max_issues=0,
    )

    diagnostics.accept()
    diagnostics.reject(2, "malformed_record")
    diagnostics.reject(3, "invalid_format")

    assert diagnostics.issues == []

    result = build_input_integrity(
        source_failures=[],
        parser_diagnostics=[diagnostics],
    )

    assert result == {
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
    }


def test_input_integrity_reports_quarantine_retention_separately():
    quarantine = QuarantineBuffer(
        max_records=1,
        max_record_bytes=128,
    )

    diagnostics = ParserDiagnostics(
        source="firewall",
        max_issues=0,
        quarantine=quarantine,
    )

    diagnostics.accept()

    diagnostics.reject(
        2,
        "too_few_fields",
        raw_record="PRIVATE_FIREWALL_RECORD_A",
    )

    diagnostics.reject(
        3,
        "invalid_port",
        raw_record="PRIVATE_FIREWALL_RECORD_B",
    )

    result = build_input_integrity(
        source_failures=[],
        parser_diagnostics=[diagnostics],
    )

    assert result is not None
    assert result["status"] == "incomplete"

    assert result["parser_diagnostics"] == [
        {
            "source": "firewall",
            "read": 3,
            "accepted": 1,
            "rejected": 2,
            "reason_codes": [],
            "issues_dropped": 2,
            "quarantine": {
                "retained": 1,
                "dropped": 1,
            },
        },
    ]

    assert "PRIVATE_FIREWALL_RECORD_A" not in repr(result)
    assert "PRIVATE_FIREWALL_RECORD_B" not in repr(result)

    assert diagnostics.issues_dropped == 2
    assert quarantine.dropped == 1
