import pytest

import src.application.source_isolation as isolation


@pytest.mark.parametrize(
    "events",
    [
        [],
        ["valid_event"],
    ],
    ids=["empty_success", "nonempty_success"],
)
def test_parse_isolated_source_with_status_preserves_success(
    events,
):
    source_failures = []

    result = isolation.parse_isolated_source_with_status(
        source="nmap",
        parse=lambda: events,
        source_failures=source_failures,
    )

    assert result.events == events
    assert result.failed is False
    assert source_failures == []


@pytest.mark.parametrize(
    ("exception_type", "expected_reason"),
    [
        (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_denied"),
    ],
    ids=["file_not_found", "permission_denied"],
)
def test_parse_isolated_source_with_status_distinguishes_failure(
    exception_type,
    expected_reason,
):
    def failed_parser():
        raise exception_type(
            "secret=/private/internal/source.log"
        )

    source_failures = []

    result = isolation.parse_isolated_source_with_status(
        source="nmap",
        parse=failed_parser,
        source_failures=source_failures,
    )

    assert result.events == []
    assert result.failed is True

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("nmap", expected_reason),
    ]

    assert "secret=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    "exception_type",
    [FileNotFoundError, PermissionError],
    ids=["file_not_found", "permission_denied"],
)
def test_source_isolation_status_preserves_fail_fast(
    exception_type,
):
    def failed_parser():
        raise exception_type(
            "sensitive=/private/internal/source.log"
        )

    with pytest.raises(exception_type):
        isolation.parse_isolated_source_with_status(
            source="nmap",
            parse=failed_parser,
            source_failures=None,
        )


@pytest.mark.parametrize(
    "exception_type",
    [ValueError, TypeError],
    ids=["value_error", "type_error"],
)
@pytest.mark.parametrize(
    "with_collector",
    [False, True],
    ids=["without_collector", "with_collector"],
)
def test_source_isolation_status_propagates_programming_error(
    exception_type,
    with_collector,
):
    def broken_parser():
        raise exception_type(
            "programming_error_do_not_echo"
        )

    source_failures = [] if with_collector else None

    with pytest.raises(
        exception_type,
        match="programming_error_do_not_echo",
    ):
        isolation.parse_isolated_source_with_status(
            source="windows_events",
            parse=broken_parser,
            source_failures=source_failures,
        )

    if source_failures is not None:
        assert source_failures == []


@pytest.mark.parametrize(
    "events",
    [
        [],
        ["valid_event"],
    ],
    ids=["empty_success", "nonempty_success"],
)
def test_source_isolation_legacy_interface_preserves_list(
    events,
):
    source_failures = []

    result = isolation.parse_isolated_source(
        source="nginx",
        parse=lambda: events,
        source_failures=source_failures,
    )

    assert isinstance(result, list)
    assert result == events
    assert source_failures == []
