"""How results leave the application."""

from typing import Protocol, TextIO

from vulnrank.domain.models import Report


class Reporter(Protocol):
    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        """Write the report; `limit` caps the findings listed, never the summary."""
        ...
