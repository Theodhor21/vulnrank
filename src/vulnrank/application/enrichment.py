"""Combine the threat-intelligence ports into one Enrichment per CVE."""

from collections.abc import Iterable

from vulnrank.domain.models import Enrichment, EpssScore, KevEntry
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog


def enrich(
    cve_ids: Iterable[str], epss: ExploitProbability, kev: KnownExploitedCatalog
) -> dict[str, Enrichment]:
    unique = sorted(set(cve_ids))
    scores = epss.scores(unique)
    known = kev.lookup(unique)
    return {cve: _combine(scores.get(cve), known.get(cve)) for cve in unique}


def _combine(score: EpssScore | None, kev: KevEntry | None) -> Enrichment:
    return Enrichment(
        epss_score=score.score if score else None,
        epss_percentile=score.percentile if score else None,
        in_kev=kev is not None,
        kev_date_added=kev.date_added if kev else None,
    )
