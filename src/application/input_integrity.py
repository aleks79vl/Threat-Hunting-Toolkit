"""Build safe input integrity metadata for reporting."""

from src.application.source_failure import SourceFailure
from src.parsers.parser_diagnostics import ParserDiagnostics


def build_input_integrity(
    *,
    source_failures: list[SourceFailure],
    parser_diagnostics: list[ParserDiagnostics],
) -> dict | None:
    """Summarize known source failures and rejected records.

    No raw records, file paths, or exception messages
    are included in the report metadata.
    """

    rejected_sources = [
        diagnostics
        for diagnostics in parser_diagnostics
        if diagnostics.rejected > 0
    ]

    if not source_failures and not rejected_sources:
        return None

    result = {
        "status": "incomplete",
        "source_failures": [
            {
                "source": failure.source,
                "reason": failure.reason,
            }
            for failure in source_failures
        ],
        "parser_diagnostics": [
            {
                "source": diagnostics.source,
                "read": diagnostics.read,
                "accepted": diagnostics.accepted,
                "rejected": diagnostics.rejected,
                "reason_codes": sorted({
                    issue.reason
                    for issue in diagnostics.issues
                }),
                "issues_dropped": diagnostics.issues_dropped,
            }
            for diagnostics in rejected_sources
        ],
    }

    for diagnostics, entry in zip(
        rejected_sources,
        result["parser_diagnostics"],
        strict=True,
    ):
        quarantine = diagnostics.quarantine

        if quarantine is not None:
            entry["quarantine"] = {
                "retained": len(quarantine.records),
                "dropped": quarantine.dropped,
            }

    return result
