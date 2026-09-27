"""The use case: load -> deduplicate -> enrich -> score -> rank."""

from collections.abc import Callable

from vulnrank.application.enrichment import enrich
from vulnrank.domain.dedup import deduplicate
from vulnrank.domain.models import Asset, Report
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import rank, score
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog
from vulnrank.ports.sources import FindingSource

AssetLookup = Callable[[str], Asset]


def prioritise(
    source: FindingSource,
    epss: ExploitProbability,
    kev: KnownExploitedCatalog,
    *,
    asset_for: AssetLookup,
    policy: ScoringPolicy,
) -> Report:
    loaded = source.load()
    unique = deduplicate(loaded)
    enrichment = enrich((f.vulnerability.cve_id for f in unique), epss, kev)
    scored = [
        score(f, enrichment[f.vulnerability.cve_id], asset_for(f.target), policy) for f in unique
    ]
    return Report(
        findings=tuple(rank(scored)),
        scanned=len(loaded),
        duplicates_removed=len(loaded) - len(unique),
    )
