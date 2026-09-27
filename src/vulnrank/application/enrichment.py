"""Combine the threat-intelligence ports into one Enrichment per CVE."""

from collections.abc import Iterable

from vulnrank.domain.models import Enrichment, EpssScore, KevEntry
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog


def enrich(
    vuln_ids: Iterable[str], epss: ExploitProbability, kev: KnownExploitedCatalog
) -> dict[str, Enrichment]:
    """One Enrichment per advisory ID; only CVE IDs are looked up (EPSS and KEV cover CVEs)."""
    unique = sorted(set(vuln_ids))
    cves = [vuln_id for vuln_id in unique if vuln_id.startswith("CVE-")]
    scores = epss.scores(cves)
    known = kev.lookup(cves)
    return {vuln_id: _combine(scores.get(vuln_id), known.get(vuln_id)) for vuln_id in unique}


def _combine(score: EpssScore | None, kev: KevEntry | None) -> Enrichment:
    return Enrichment(
        epss_score=score.score if score else None,
        epss_percentile=score.percentile if score else None,
        in_kev=kev is not None,
        kev_date_added=kev.date_added if kev else None,
    )
