"""Shared diagnostics contract for parser hardening."""

from dataclasses import dataclass, field

import re

from src.parsers.quarantine_buffer import QuarantineBuffer


_REASON_CODE_PATTERN = re.compile(
    r"[a-z][a-z0-9_]{0,63}"
)


@dataclass(frozen=True)
class ParserIssue:
    """Metadata describing a rejected input record."""

    line_number: int
    reason: str


@dataclass
class ParserDiagnostics:
    """Track accepted and rejected records per source."""

    source: str

    read: int = 0
    accepted: int = 0
    rejected: int = 0

    issues: list[ParserIssue] = field(default_factory=list)

    max_issues: int = field(
        default=100,
        kw_only=True,
    )

    issues_dropped: int = field(
        default=0,
        init=False,
    )

    quarantine: QuarantineBuffer | None = field(
        default=None,
        kw_only=True,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Validate diagnostics configuration."""

        if type(self.max_issues) is not int or self.max_issues < 0:
            raise ValueError(
                "max_issues must be a non-negative integer"
            )

    def accept(self) -> None:
        """Record one successfully parsed input record."""

        self.read += 1
        self.accepted += 1

    def reject(
        self,
        line_number: int,
        reason: str,
        *,
        raw_record: str | None = None,
    ) -> None:
        """Record a rejection and optionally quarantine raw input."""

        if type(line_number) is not int or line_number <= 0:
            raise ValueError(
                "line_number must be a positive integer"
            )

        if (
            not isinstance(reason, str)
            or _REASON_CODE_PATTERN.fullmatch(reason) is None
        ):
            raise ValueError(
                "reason must be a lowercase code "
                "starting with a letter, containing only "
                "letters, digits or underscores, "
                "with a maximum length of 64"
            )

        quarantine = self.quarantine

        if quarantine is not None:
            if not isinstance(raw_record, str):
                raise ValueError(
                    "raw_record is required when quarantine is enabled"
                )

        self.read += 1
        self.rejected += 1

        if len(self.issues) < self.max_issues:
            self.issues.append(
                ParserIssue(
                    line_number=line_number,
                    reason=reason,
                )
            )
        else:
            self.issues_dropped += 1

        if quarantine is not None:
            quarantine.capture(
                source=self.source,
                line_number=line_number,
                reason_code=reason,
                raw_record=raw_record,
            )
