from src.parsers.firewall_parser import parse_firewall_log
from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.quarantine_buffer import QuarantineBuffer

import pytest


def test_parse_firewall_log_returns_events():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    assert len(events) == 10


def test_first_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[0]

    assert event.source == "Firewall"
    assert event.event_type == "ALLOW"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.77"
    assert event.dst_port == 3389
    assert event.protocol == "TCP"


def test_second_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[1]

    assert event.event_type == "DENY"
    assert event.dst_port == 3389


def test_last_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[-1]

    assert event.event_type == "DENY"
    assert event.dst_port == 1433


def test_timestamp():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[0]

    assert event.timestamp == "2026-06-27 09:00:15"


def test_firewall_parser_continues_after_short_line(
    tmp_path,
):
    log_path = tmp_path / "firewall.log"

    log_path.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",

            "2026-06-27 09:00:16 DENY TCP 192.168.1.20",

            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.80 53",
        ]) + "\n",
        encoding="utf-8",
    )

    events = parse_firewall_log(str(log_path))

    assert len(events) == 2
    assert events[0].event_type == "ALLOW"
    assert events[0].dst_port == 3389

    assert events[1].event_type == "DENY"
    assert events[1].dst_port == 53


def test_firewall_parser_records_short_line_diagnostics(
    tmp_path,
):
    log_path = tmp_path / "firewall.log"

    log_path.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",

            "2026-06-27 09:00:16 DENY TCP 192.168.1.20",

            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.80 53",
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="firewall")

    events = parse_firewall_log(
        str(log_path),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == "too_few_fields"

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_port",
    ["-1", "65536"],
)
def test_firewall_parser_rejects_out_of_range_port(
    tmp_path,
    invalid_port,
):
    log_path = tmp_path / "firewall.log"

    log_path.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",

            "",

            "2026-06-27 09:00:16 DENY TCP "
            f"192.168.1.20 192.168.1.80 {invalid_port}",

            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.90 53",
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="firewall")

    events = parse_firewall_log(
        str(log_path),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.dst_port for event in events] == [
        3389,
        53,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 3
    assert diagnostics.issues[0].reason == (
        "invalid_port_range"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_port",
    ["abc", "22.5"],
)
def test_firewall_parser_rejects_non_numeric_port(
    tmp_path,
    invalid_port,
):
    log_path = tmp_path / "firewall.log"

    log_path.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",

            "",

            "2026-06-27 09:00:16 DENY TCP "
            f"192.168.1.20 192.168.1.80 {invalid_port}",

            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.90 53",
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="firewall")

    events = parse_firewall_log(
        str(log_path),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.dst_port for event in events] == [
        3389,
        53,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 3
    assert diagnostics.issues[0].reason == "invalid_port"

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_firewall_parser_quarantines_rejected_record_and_continues(
    tmp_path,
):
    log_file = tmp_path / "firewall_quarantine.log"

    malformed_record = (
        "2026-06-27 09:00:16 DENY TCP "
        "192.168.1.20 PRIVATE_SECRET_DO_NOT_EXPORT"
    )

    log_file.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",
            malformed_record,
            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.80 53",
        ]) + "\n",
        encoding="utf-8",
    )

    quarantine = QuarantineBuffer(
        max_records=2,
        max_record_bytes=512,
    )

    diagnostics = ParserDiagnostics(
        source="firewall",
        quarantine=quarantine,
    )

    events = parse_firewall_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.dst_port for event in events] == [
        3389,
        53,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "too_few_fields"),
    ]

    assert len(quarantine.records) == 1
    assert quarantine.dropped == 0

    record = quarantine.records[0]

    assert record.source == "firewall"
    assert record.line_number == 2
    assert record.reason_code == "too_few_fields"
    assert record.raw_record == malformed_record

    assert "PRIVATE_SECRET_DO_NOT_EXPORT" not in repr(
        diagnostics
    )
    assert "PRIVATE_SECRET_DO_NOT_EXPORT" not in repr(
        quarantine
    )


def test_firewall_quarantine_overflow_preserves_all_rejection_counts(
    tmp_path,
):
    log_file = tmp_path / "firewall_quarantine_overflow.log"

    malformed_short = (
        "2026-06-27 09:00:16 DENY TCP 192.168.1.20"
    )
    malformed_port = (
        "2026-06-27 09:00:17 DENY TCP "
        "192.168.1.20 192.168.1.30 SECRET_PORT"
    )
    malformed_range = (
        "2026-06-27 09:00:18 DENY TCP "
        "192.168.1.20 192.168.1.30 65536"
    )

    records = [
        "2026-06-27 09:00:15 ALLOW TCP "
        "192.168.1.10 192.168.1.77 3389",
        malformed_short,
        malformed_port,
        malformed_range,
        "2026-06-27 09:00:19 DENY UDP "
        "192.168.1.30 192.168.1.80 53",
    ]

    log_file.write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
    )

    quarantine = QuarantineBuffer(
        max_records=1,
        max_record_bytes=512,
    )

    diagnostics = ParserDiagnostics(
        source="firewall",
        quarantine=quarantine,
    )

    events = parse_firewall_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.dst_port for event in events] == [
        3389,
        53,
    ]

    assert diagnostics.read == 5
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 3

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "too_few_fields"),
        (3, "invalid_port"),
        (4, "invalid_port_range"),
    ]

    assert diagnostics.issues_dropped == 0

    assert len(quarantine.records) == 1
    assert quarantine.dropped == 2

    retained = quarantine.records[0]

    assert retained.source == "firewall"
    assert retained.line_number == 2
    assert retained.reason_code == "too_few_fields"
    assert retained.raw_record == malformed_short

    assert all(
        event.raw_event not in {
            malformed_short,
            malformed_port,
            malformed_range,
        }
        for event in events
    )

    assert malformed_short not in repr(quarantine)
    assert malformed_short not in repr(diagnostics)
