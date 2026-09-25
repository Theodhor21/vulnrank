"""Rule-based prioritisation: deterministic, and every tier comes with the rules that set it.

Tiers are checked from P1 down. The first tier with at least one matching rule wins, and every
matching rule of that tier becomes a reason. Context (exposure, fix availability) is appended
but never changes the tier.
"""

import math
from collections.abc import Callable, Iterable

from vulnrank.domain.models import (
    Asset,
    Criticality,
    Enrichment,
    Finding,
    Priority,
    Reason,
    ScoredFinding,
    Vulnerability,
)
from vulnrank.domain.policy import ScoringPolicy

Rule = Callable[[Vulnerability, Enrichment, Asset, ScoringPolicy], str | None]


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _in_kev(_v: Vulnerability, e: Enrichment, _a: Asset, _p: ScoringPolicy) -> str | None:
    if not e.in_kev:
        return None
    if e.kev_date_added is None:
        return "in CISA KEV"
    return f"in CISA KEV (added {e.kev_date_added.isoformat()})"


def _likely_exploit_on_important_asset(
    _v: Vulnerability, e: Enrichment, a: Asset, p: ScoringPolicy
) -> str | None:
    threshold = p.p1_epss_on_high_criticality
    if e.epss_score is None or e.epss_score < threshold:
        return None
    if not a.criticality.is_at_least(Criticality.HIGH):
        return None
    return f"EPSS {_pct(e.epss_score)} ≥ {_pct(threshold)} on a {a.criticality} asset"


def _exploitable_on_exposed_critical_asset(
    _v: Vulnerability, e: Enrichment, a: Asset, p: ScoringPolicy
) -> str | None:
    threshold = p.p1_epss_on_exposed_critical
    if e.epss_score is None or e.epss_score < threshold:
        return None
    if not (a.internet_exposed and a.criticality is Criticality.CRITICAL):
        return None
    return f"EPSS {_pct(e.epss_score)} ≥ {_pct(threshold)} on an internet-exposed critical asset"


def _elevated_epss(_v: Vulnerability, e: Enrichment, _a: Asset, p: ScoringPolicy) -> str | None:
    if e.epss_score is None or e.epss_score < p.p2_epss:
        return None
    return f"EPSS {_pct(e.epss_score)} ≥ {_pct(p.p2_epss)}"


def _critical_cvss_on_important_asset(
    v: Vulnerability, _e: Enrichment, a: Asset, p: ScoringPolicy
) -> str | None:
    threshold = p.p2_cvss_on_high_criticality
    if v.cvss_score is None or v.cvss_score < threshold:
        return None
    if not a.criticality.is_at_least(Criticality.HIGH):
        return None
    return f"CVSS {v.cvss_score:.1f} ≥ {threshold:.1f} on a {a.criticality} asset"


def _high_cvss(v: Vulnerability, _e: Enrichment, _a: Asset, p: ScoringPolicy) -> str | None:
    if v.cvss_score is None or v.cvss_score < p.p3_cvss:
        return None
    return f"CVSS {v.cvss_score:.1f} ≥ {p.p3_cvss:.1f}"


RULES: tuple[tuple[Priority, tuple[Rule, ...]], ...] = (
    (
        Priority.P1,
        (_in_kev, _likely_exploit_on_important_asset, _exploitable_on_exposed_critical_asset),
    ),
    (Priority.P2, (_elevated_epss, _critical_cvss_on_important_asset)),
    (Priority.P3, (_high_cvss,)),
)

NO_RULE_MATCHED = "no escalation rule matched"


def score(
    finding: Finding, enrichment: Enrichment, asset: Asset, policy: ScoringPolicy
) -> ScoredFinding:
    priority, decisive = _classify(finding.vulnerability, enrichment, asset, policy)
    return ScoredFinding(
        finding=finding,
        enrichment=enrichment,
        asset=asset,
        priority=priority,
        reasons=(*decisive, *_context(finding, asset)),
    )


def _classify(
    v: Vulnerability, e: Enrichment, a: Asset, p: ScoringPolicy
) -> tuple[Priority, tuple[Reason, ...]]:
    for tier, rules in RULES:
        texts = [text for rule in rules if (text := rule(v, e, a, p)) is not None]
        if texts:
            return tier, tuple(Reason(text=text, tier=tier) for text in texts)
    return Priority.P4, (Reason(text=NO_RULE_MATCHED, tier=Priority.P4),)


def _context(finding: Finding, asset: Asset) -> tuple[Reason, ...]:
    reasons: list[Reason] = []
    if asset.internet_exposed:
        reasons.append(Reason(text="asset is internet-exposed"))
    fixed = finding.vulnerability.fixed_version
    if fixed:
        reasons.append(Reason(text=f"fix available ({finding.component.version} → {fixed})"))
    else:
        reasons.append(Reason(text="no fix available"))
    return tuple(reasons)


def rank(findings: Iterable[ScoredFinding]) -> list[ScoredFinding]:
    """Sort by tier, then EPSS, then CVSS (both descending, unknown last), then fixable first."""
    return sorted(findings, key=_sort_key)


def _sort_key(scored: ScoredFinding) -> tuple[int, float, float, bool, str, str, str]:
    vulnerability = scored.finding.vulnerability
    return (
        scored.priority.rank,
        _descending(scored.enrichment.epss_score),
        _descending(vulnerability.cvss_score),
        not vulnerability.fix_available,
        # Stable, deterministic tie-breakers so output never depends on input order.
        vulnerability.cve_id,
        scored.finding.component.name,
        scored.finding.target,
    )


def _descending(value: float | None) -> float:
    return math.inf if value is None else -value
