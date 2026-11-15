"""Bounded in-memory quarantine for rejected parser records."""

from dataclasses import dataclass, field
import re


_REASON_CODE_PATTERN = re.compile(
    r"[a-z][a-z0-9_]{0,63}"
)


@dataclass(frozen=True, slots=True)
class QuarantinedRecord:
    """Rejected record retained outside normalized events."""

    source: str
    line_number: int
    reason_code: str
    raw_record: str = field(repr=False)


@dataclass(slots=True)
class QuarantineBuffer:
    """Bounded, opt-in quarantine without persistent storage."""

    max_records: int
    max_record_bytes: int

    records: list[QuarantinedRecord] = field(
        default_factory=list,
        init=False,
        repr=False,
    )

    dropped: int = field(
        default=0,
        init=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.max_records) is not int
            or self.max_records < 0
        ):
            raise ValueError(
                "max_records must be a non-negative integer"
            )

        if (
            type(self.max_record_bytes) is not int
            or self.max_record_bytes < 0
        ):
            raise ValueError(
                "max_record_bytes must be a non-negative integer"
            )

    def capture(
        self,
        *,
        source: str,
        line_number: int,
        reason_code: str,
        raw_record: str,
    ) -> bool:
        """Retain a rejected record if capacity permits.

        Returns True when retained, otherwise False.
        Never includes raw input in error messages.
        """

        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty string")

        if type(line_number) is not int or line_number <= 0:
            raise ValueError(
                "line_number must be a positive integer"
            )

        if (
            not isinstance(reason_code, str)
            or _REASON_CODE_PATTERN.fullmatch(
                reason_code
            ) is None
        ):
            raise ValueError("invalid reason_code")

        if not isinstance(raw_record, str):
            raise ValueError("raw_record must be a string")

        if len(raw_record) > self.max_record_bytes:
            self.dropped += 1
            return False

        try:
            record_size = len(raw_record.encode("utf-8"))
        except UnicodeEncodeError:
            self.dropped += 1
            return False

        if (
            record_size > self.max_record_bytes
            or len(self.records) >= self.max_records
        ):
            self.dropped += 1
            return False

        self.records.append(
            QuarantinedRecord(
                source=source,
                line_number=line_number,
                reason_code=reason_code,
                raw_record=raw_record,
            )
        )

        return True
