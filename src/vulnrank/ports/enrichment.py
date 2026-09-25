"""Threat-intelligence lookups the application depends on."""

from collections.abc import Collection, Mapping
from typing import Protocol

from vulnrank.domain.models import EpssScore, KevEntry


class ExploitProbability(Protocol):
    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        """EPSS scores for the CVEs that have one. Failures are logged, never raised."""
        ...


class KnownExploitedCatalog(Protocol):
    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        """The subset of `cve_ids` known to be exploited. Failures are logged, never raised."""
        ...
