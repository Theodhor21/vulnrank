"""Threat-intelligence lookups the application depends on."""

from collections.abc import Collection, Mapping
from typing import Protocol

from vulnrank.domain.models import EpssScore, KevEntry


class ExploitProbability(Protocol):
    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        """EPSS scores for the CVEs that have one. Failures are logged, never raised."""
        ...

    def issues(self) -> tuple[str, ...]:
        """Why data is missing after `scores`, e.g. the API failed and nothing was cached."""
        ...


class KnownExploitedCatalog(Protocol):
    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        """The subset of `cve_ids` known to be exploited. Failures are logged, never raised."""
        ...

    def issues(self) -> tuple[str, ...]:
        """Why the catalog is missing after `lookup`, e.g. offline without a cached copy."""
        ...
