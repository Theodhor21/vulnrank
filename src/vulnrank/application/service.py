"""The use case: load -> deduplicate -> enrich -> score -> rank."""

import logging
from collections.abc import Callable
from datetime import date

from vulnrank.application.enrichment import enrich
from vulnrank.domain.baseline import Baseline, compare_to_baseline
from vulnrank.domain.dedup import deduplicate
from vulnrank.domain.models import Asset, Finding, Report
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import rank, score
from vulnrank.domain.suppression import IgnoreRule, VexStatement, apply_suppressions
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
    rules: tuple[IgnoreRule, ...] = (),
    statements: tuple[VexStatement, ...] = (),
    today: date | None = None,
    baseline: Baseline | None = None,
) -> Report:
    """`target`, when given, replaces the scan's own name (e.g. a file name) on every finding.

    Suppressed findings (VEX, ignore rules) are scored too, so a warning can say when one of
    them is known to be exploited, but they are reported apart and never ranked.
    """
    loaded = source.load()
    findings = [_renamed(f, target) for f in loaded.findings] if target else list(loaded.findings)
    scanned = len(findings) + loaded.skipped
    logger.info("loaded %d findings from %d records", len(findings), scanned)
    unique = deduplicate(findings)
    enrichment = enrich((f.vulnerability.vuln_id for f in unique), epss, kev)
    scored = [
        score(f, enrichment[f.vulnerability.vuln_id], asset_for(f.target), policy) for f in unique
    ]
    result = apply_suppressions(
        scored, rules=rules, statements=statements, today=today or date.today()
    )
    for rule in result.expired:
        logger.warning(
            "ignore rule for %s expired on %s; it no longer applies (%s)",
            rule.label,
            rule.expires,
            rule.source,
        )
    for suppressed in result.suppressed:
        if suppressed.in_kev:
            logger.warning(
                "suppressed %s is in CISA KEV (%s: %s)",
                suppressed.scored.finding.vulnerability.vuln_id,
                suppressed.source,
                suppressed.reason,
            )
    ranked = tuple(rank(result.kept))
    resolved: int | None = None
    if baseline is not None:
        if not baseline.complete:
            logger.warning(
                "the baseline does not list every finding (it was written with --top); "
                "findings missing from it count as new"
            )
        comparison = compare_to_baseline(ranked, baseline)
        ranked, resolved = comparison.findings, comparison.resolved
    return Report(
        findings=ranked,
        baseline_resolved=resolved,
        suppressed=result.suppressed,
        scanned=scanned,
        skipped=loaded.skipped,
        duplicates_removed=len(findings) - len(unique),
        enrichment_issues=(*epss.issues(), *kev.issues()),
    )


def _renamed(finding: Finding, target: str) -> Finding:
    return finding.model_copy(update={"target": target})
