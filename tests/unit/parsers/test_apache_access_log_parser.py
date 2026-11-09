import pytest

from src.parsers.apache_access_log_parser import (
    parse_apache_access_log,
    parse_apache_vhost_access_log,
)
from src.parsers.parser_diagnostics import ParserDiagnostics


def test_parse_apache_access_log_returns_events():
    events = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )

    assert len(events) == 11


def test_apache_access_event_contains_request_details():
    event = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )[0]

    assert event.source == "apache"
    assert event.client_ip == "192.168.1.10"
    assert event.method == "GET"
    assert event.path == "/"
    assert event.protocol == "HTTP/1.1"
    assert event.status_code == 200
    assert event.response_size == 1024


def test_apache_access_event_preserves_user_agent():
    event = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )[4]

    assert event.user_agent == "sqlmap/1.7"
    assert "OR" in event.path


@pytest.mark.parametrize(
    ("parser", "with_vhost"),
    [
        (parse_apache_access_log, False),
        (parse_apache_vhost_access_log, True),
    ],
    ids=["combined", "vhost_combined"],
)
def test_apache_parser_accepts_dash_response_size(
    tmp_path,
    parser,
    with_vhost,
):
    log_file = tmp_path / "apache_response_size_dash.log"

    records = [
        (
            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:00 +0000] '
            '"GET /first HTTP/1.1" 200 1024 '
            '"-" "pytest"'
        ),
        (
            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:01 +0000] '
            '"GET /zero-body HTTP/1.1" 204 - '
            '"-" "pytest"'
        ),
        (
            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:02 +0000] '
            '"GET /last HTTP/1.1" 200 512 '
            '"-" "pytest"'
        ),
    ]

    if with_vhost:
        records = [
            f"api.example.com {record}"
            for record in records
        ]

    log_file.write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
    )

    events = parser(str(log_file))

    assert len(events) == 3

    assert [event.path for event in events] == [
        "/first",
        "/zero-body",
        "/last",
    ]

    assert [event.response_size for event in events] == [
        1024,
        0,
        512,
    ]

    assert [event.status_code for event in events] == [
        200,
        204,
        200,
    ]

    assert all(event.source == "apache" for event in events)

    if with_vhost:
        assert all(
            event.virtual_host == "api.example.com"
            for event in events
        )


@pytest.mark.parametrize(
    ("parser", "with_vhost", "source"),
    [
        (
            parse_apache_access_log,
            False,
            "apache_access",
        ),
        (
            parse_apache_vhost_access_log,
            True,
            "apache_vhost",
        ),
    ],
    ids=["combined", "vhost_combined"],
)
def test_apache_parser_records_invalid_log_format(
    tmp_path,
    parser,
    with_vhost,
    source,
):
    log_file = tmp_path / "apache_mixed.log"

    records = [
        (
            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:00 +0000] '
            '"GET /first HTTP/1.1" 200 1024 '
            '"-" "pytest"'
        ),
        "",
        "invalid apache record secret=do_not_echo",
        (
            '192.0.2.20 - - '
            '[21/Oct/2026:10:00:02 +0000] '
            '"GET /last HTTP/1.1" 204 - '
            '"-" "pytest"'
        ),
    ]

    if with_vhost:
        records = [
            f"api.example.com {record}"
            if record and record.startswith("192.0.2.")
            else record
            for record in records
        ]

    log_file.write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source=source)

    events = parser(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.response_size for event in events] == [
        1024,
        0,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (3, "invalid_log_format"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    assert "secret=do_not_echo" not in repr(
        diagnostics.issues
    )


@pytest.mark.parametrize(
    ("parser", "with_vhost", "source"),
    [
        (
            parse_apache_access_log,
            False,
            "apache_access",
        ),
        (
            parse_apache_vhost_access_log,
            True,
            "apache_vhost",
        ),
    ],
    ids=["combined", "vhost_combined"],
)
def test_apache_parser_rejects_trailing_garbage(
    tmp_path,
    parser,
    with_vhost,
    source,
):
    log_file = tmp_path / "apache_trailing_garbage.log"

    first_record = (
        '192.0.2.10 - - '
        '[21/Oct/2026:10:00:00 +0000] '
        '"GET /first HTTP/1.1" 200 1024 '
        '"-" "pytest"'
    )

    invalid_record = (
        '192.0.2.20 - - '
        '[21/Oct/2026:10:00:01 +0000] '
        '"GET /invalid HTTP/1.1" 200 512 '
        '"-" "pytest" '
        'secret=do_not_echo'
    )

    last_record = (
        '192.0.2.30 - - '
        '[21/Oct/2026:10:00:02 +0000] '
        '"GET /last HTTP/1.1" 204 - '
        '"-" "pytest"'
    )

    records = [
        first_record,
        invalid_record,
        last_record,
    ]

    if with_vhost:
        records = [
            f"api.example.com {record}"
            for record in records
        ]

    log_file.write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source=source)

    events = parser(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.response_size for event in events] == [
        1024,
        0,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "invalid_log_format"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    assert "secret=do_not_echo" not in repr(
        diagnostics.issues
    )

    assert all(
        "secret=do_not_echo" not in event.raw_event
        for event in events
    )
