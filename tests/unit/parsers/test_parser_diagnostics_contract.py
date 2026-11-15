import pytest

from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.quarantine_buffer import QuarantineBuffer


def test_parser_diagnostics_counts_record_outcomes():
    diagnostics = ParserDiagnostics(source="firewall")

    # First valid record.
    diagnostics.accept()

    # Malformed second record.
    diagnostics.reject(
        line_number=2,
        reason="too_few_fields",
    )

    # Processing continues with the third record.
    diagnostics.accept()

    assert diagnostics.source == "firewall"
    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert (
        diagnostics.issues[0].reason
        == "too_few_fields"
    )


def test_parser_diagnostics_isolates_sources():
    firewall = ParserDiagnostics(source="firewall")
    nginx = ParserDiagnostics(source="nginx")

    firewall.reject(
        line_number=1,
        reason="too_few_fields",
    )

    nginx.accept()

    assert firewall.read == 1
    assert firewall.accepted == 0
    assert firewall.rejected == 1
    assert len(firewall.issues) == 1

    assert nginx.read == 1
    assert nginx.accepted == 1
    assert nginx.rejected == 0
    assert nginx.issues == []

    assert firewall.issues is not nginx.issues

@pytest.mark.parametrize(
    "line_number, reason",
    [
        (0, "invalid_record"),
        (-1, "invalid_record"),
        (True, "invalid_record"),
        ("2", "invalid_record"),
        (2, ""),
        (2, "   "),
        (2, None),
        (2, 123),
    ],
)
def test_parser_diagnostics_rejects_invalid_issue_metadata(
    line_number,
    reason,
):
    diagnostics = ParserDiagnostics(source="firewall")

    with pytest.raises(ValueError):
        diagnostics.reject(
            line_number=line_number,
            reason=reason,
        )

    # Invalid metadata must not affect counters.
    assert diagnostics.read == 0
    assert diagnostics.accepted == 0
    assert diagnostics.rejected == 0
    assert diagnostics.issues == []



def test_parser_diagnostics_limits_stored_issues():
    diagnostics = ParserDiagnostics(
        source="firewall",
        max_issues=2,
    )

    for line_number in range(1, 6):
        diagnostics.reject(
            line_number=line_number,
            reason="too_few_fields",
        )

    assert diagnostics.read == 5
    assert diagnostics.accepted == 0
    assert diagnostics.rejected == 5

    assert len(diagnostics.issues) == 2
    assert diagnostics.issues_dropped == 3

    assert [
        issue.line_number
        for issue in diagnostics.issues
    ] == [1, 2]

    assert (
        diagnostics.rejected
        == len(diagnostics.issues)
        + diagnostics.issues_dropped
    )


def test_parser_diagnostics_allows_zero_issue_storage():
    diagnostics = ParserDiagnostics(
        source="waf",
        max_issues=0,
    )

    diagnostics.reject(
        line_number=1,
        reason="invalid_root_type",
    )

    assert diagnostics.read == 1
    assert diagnostics.rejected == 1
    assert diagnostics.issues == []
    assert diagnostics.issues_dropped == 1


def test_parser_diagnostics_default_issue_limit():
    diagnostics = ParserDiagnostics(source="nginx")

    for line_number in range(1, 103):
        diagnostics.reject(
            line_number=line_number,
            reason="invalid_json",
        )

    assert diagnostics.max_issues == 100
    assert len(diagnostics.issues) == 100
    assert diagnostics.issues_dropped == 2
    assert diagnostics.rejected == 102


@pytest.mark.parametrize(
    "invalid_limit",
    [-1, True, "100"],
)
def test_parser_diagnostics_rejects_invalid_issue_limit(
    invalid_limit,
):
    with pytest.raises(ValueError, match="max_issues"):
        ParserDiagnostics(
            source="firewall",
            max_issues=invalid_limit,
        )


@pytest.mark.parametrize(
    "invalid_reason",
    [
        "invalid json",
        "invalid-json",
        "Invalid_JSON",
        "password=secret",
        "Authorization: Bearer secret-token",
        "../sensitive/file",
        "a" * 65,
    ],
)
def test_parser_diagnostics_rejects_unsafe_reason_codes(
    invalid_reason,
):
    diagnostics = ParserDiagnostics(source="firewall")

    with pytest.raises(ValueError, match="reason"):
        diagnostics.reject(
            line_number=1,
            reason=invalid_reason,
        )

    assert diagnostics.read == 0
    assert diagnostics.accepted == 0
    assert diagnostics.rejected == 0
    assert diagnostics.issues == []
    assert diagnostics.issues_dropped == 0


def test_parser_diagnostics_opt_in_quarantine_preserves_independent_counters():
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

    assert diagnostics.read == 3
    assert diagnostics.accepted == 1
    assert diagnostics.rejected == 2

    assert diagnostics.issues == []
    assert diagnostics.issues_dropped == 2

    assert len(quarantine.records) == 1
    assert quarantine.dropped == 1

    record = quarantine.records[0]

    assert record.source == "firewall"
    assert record.line_number == 2
    assert record.reason_code == "too_few_fields"
    assert record.raw_record == "PRIVATE_FIREWALL_RECORD_A"

    assert "PRIVATE_FIREWALL_RECORD_A" not in repr(diagnostics)
    assert "PRIVATE_FIREWALL_RECORD_A" not in repr(quarantine)


def test_quarantine_requires_raw_record_before_updating_counters():
    quarantine = QuarantineBuffer(
        max_records=2,
        max_record_bytes=128,
    )

    diagnostics = ParserDiagnostics(
        source="firewall",
        quarantine=quarantine,
    )

    diagnostics.accept()

    with pytest.raises(
        ValueError,
        match="raw_record is required when quarantine is enabled",
    ):
        diagnostics.reject(
            2,
            "too_few_fields",
        )

    assert diagnostics.read == 1
    assert diagnostics.accepted == 1
    assert diagnostics.rejected == 0

    assert diagnostics.issues == []
    assert diagnostics.issues_dropped == 0

    assert quarantine.records == []
    assert quarantine.dropped == 0
