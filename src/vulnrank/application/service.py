"""The use case: load -> deduplicate -> enrich -> score -> rank."""

import logging
from collections.abc import Callable

from vulnrank.application.enrichment import enrich
from vulnrank.domain.dedup import deduplicate
from vulnrank.domain.models import Asset, Finding, Report
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import rank, score
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog
from vulnrank.ports.sources import FindingSource

logger = logging.getLogger(__name__)

AssetLookup = Callable[[str], Asset]


def prioritise(
    source: FindingSource,
    epss: ExploitProbability,
    kev: KnownExploitedCatalog,
    *,
    asset_for: AssetLookup,
    policy: ScoringPolicy,
    target: str | None = None,
) -> Report:
    """`target`, when given, replaces the scan's own name (e.g. a file name) on every finding."""
    loaded = source.load()
    findings = [_renamed(f, target) for f in loaded.findings] if target else list(loaded.findings)
    scanned = len(findings) + loaded.skipped
    logger.info("loaded %d findings from %d records", len(findings), scanned)
    unique = deduplicate(findings)
    enrichment = enrich((f.vulnerability.vuln_id for f in unique), epss, kev)
    scored = [
        score(f, enrichment[f.vulnerability.vuln_id], asset_for(f.target), policy) for f in unique
    ]
    return Report(
        findings=tuple(rank(scored)),
        scanned=scanned,
        skipped=loaded.skipped,
        duplicates_removed=len(findings) - len(unique),
        enrichment_issues=(*epss.issues(), *kev.issues()),
    )


def _renamed(finding: Finding, target: str) -> Finding:
    return finding.model_copy(update={"target": target})
