"""Where findings come from."""

from typing import Protocol

from vulnrank.domain.models import Finding


class SourceError(Exception):
    """The input as a whole cannot be used: unreadable, not JSON, or not the expected format."""


class FindingSource(Protocol):
    def load(self) -> list[Finding]:
        """Return every valid finding; malformed records are logged and skipped."""
        ...
