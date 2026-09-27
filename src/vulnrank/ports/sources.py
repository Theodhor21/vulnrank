"""Where findings come from."""

from typing import Protocol

from vulnrank.domain.models import ScanResult


class SourceError(Exception):
    """The input as a whole cannot be used: unreadable, not JSON, or not the expected format."""


class FindingSource(Protocol):
    def load(self) -> ScanResult:
        """Every valid finding; malformed records are logged, skipped and counted."""
        ...
