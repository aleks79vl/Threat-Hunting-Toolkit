import json

from src.application.input_integrity import build_input_integrity
from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.quarantine_buffer import QuarantineBuffer


SYNTHETIC_SECRET = "SEC_API_01_QUARANTINE_NOT_REAL_4e91"


def test_quarantine_raw_credentials_are_not_exported():
    quarantine = QuarantineBuffer(
        max_records=10,
        max_record_bytes=4096,
    )

    diagnostics = ParserDiagnostics(
        source="nginx",
        quarantine=quarantine,
    )

    raw_record = (
        '{"api_key_id":"' + SYNTHETIC_SECRET + '","invalid":'
    )

    diagnostics.reject(
        line_number=1,
        reason="invalid_json",
        raw_record=raw_record,
    )

    assert len(quarantine.records) == 1
    assert quarantine.records[0].raw_record == raw_record

    report_metadata = build_input_integrity(
        source_failures=[],
        parser_diagnostics=[diagnostics],
    )

    assert report_metadata is not None

    serialized = json.dumps(report_metadata)

    assert SYNTHETIC_SECRET not in serialized
    assert "raw_record" not in serialized

    entry = report_metadata["parser_diagnostics"][0]

    assert entry["rejected"] == 1
    assert entry["quarantine"]["retained"] == 1
    assert entry["quarantine"]["dropped"] == 0
