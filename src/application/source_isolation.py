"""Shared source isolation for application pipelines."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from src.application.source_failure import SourceFailure


EventT = TypeVar("EventT")


@dataclass(frozen=True, slots=True)
class SourceParseResult(Generic[EventT]):
    """Distinguish successful parsing from source failure."""

    events: list[EventT]
    failed: bool


def parse_isolated_source_with_status(
    *,
    source: str,
    parse: Callable[[], list[EventT]],
    source_failures: list[SourceFailure] | None,
) -> SourceParseResult[EventT]:
    """Parse a source and preserve its availability status."""

    try:
        events = parse()

    except (FileNotFoundError, PermissionError) as error:
        if source_failures is None:
            raise

        reason = (
            "file_not_found"
            if isinstance(error, FileNotFoundError)
            else "permission_denied"
        )

        source_failures.append(
            SourceFailure(
                source=source,
                reason=reason,
            )
        )

        return SourceParseResult(
            events=[],
            failed=True,
        )

    return SourceParseResult(
        events=events,
        failed=False,
    )


def parse_isolated_source(
    *,
    source: str,
    parse: Callable[[], list[EventT]],
    source_failures: list[SourceFailure] | None,
) -> list[EventT]:
    """Backward-compatible source isolation interface."""

    result = parse_isolated_source_with_status(
        source=source,
        parse=parse,
        source_failures=source_failures,
    )

    return result.events
