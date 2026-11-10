"""Safe metadata for application source failures."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class SourceFailure:
    """Record a source failure without raw input or exception details."""

    source: str
    reason: Literal[
        "file_not_found",
        "permission_denied",
    ]
