"""Turn ranked findings into a fix plan: "upgrade X to version Y fixes N vulnerabilities".

Teams file tickets per upgrade, not per CVE. Findings with a fixed version are grouped per
package (target, ecosystem, name, installed version). Packages from one source that need
exactly the same fixes, such as Debian's `openssl` and `libssl1.1`, become one action.

An action targets the smallest version that fixes every advisory of the package, respecting
release branches (Trivy lists one fix per branch) and the ecosystem's version rules (see
`versions`).
"""

import math
from collections import Counter
from collections.abc import Iterable

from vulnrank.domain.models import DomainModel, FixStatus, Priority, ScoredFinding
from vulnrank.domain.scoring import rank
from vulnrank.domain.versions import upgrade_target

NOT_YET_FIXED = "not yet fixed"
NO_FIX_STATUS = {
    FixStatus.WILL_NOT_FIX: "will not fix",
    FixStatus.FIX_DEFERRED: "deferred",
    FixStatus.END_OF_LIFE: "end-of-life",
}
STATUS_ORDER = (NOT_YET_FIXED, *NO_FIX_STATUS.values())


def no_fix_status(scored: ScoredFinding) -> str:
    """Why a finding has no fix: the vendor's word, or simply not fixed yet."""
    status = scored.finding.vulnerability.status
    return NO_FIX_STATUS.get(status, NOT_YET_FIXED) if status else NOT_YET_FIXED


class FixAction(DomainModel):
    """One upgrade. Derived values are computed once, when the plan is built."""

    target: str
    ecosystem: str | None
    packages: tuple[str, ...]
    installed_version: str
    fixed_version: str
    findings: tuple[ScoredFinding, ...]  # ranked, most urgent first
    priority: Priority
    vuln_ids: tuple[str, ...]
    counts: dict[Priority, int]  # distinct vulnerabilities per tier
    kev_count: int


class FixPlan(DomainModel):
    actions: tuple[FixAction, ...]
    unfixable: tuple[ScoredFinding, ...]

    @property
    def fixable_findings(self) -> int:
        return sum(len(action.findings) for action in self.actions)

    @property
    def unfixable_by_status(self) -> dict[str, int]:
        counts = Counter(no_fix_status(scored) for scored in self.unfixable)
        return {status: counts[status] for status in STATUS_ORDER if counts[status]}


PackageKey = tuple[str, str, str, str]  # target, ecosystem, package name, installed version
MergeKey = tuple[str, str, str, frozenset[tuple[str, str]]]  # ..., (vuln, fix) pairs


def plan_fixes(findings: Iterable[ScoredFinding]) -> FixPlan:
    fixable: list[ScoredFinding] = []
    unfixable: list[ScoredFinding] = []
    for scored in findings:
        (fixable if scored.finding.vulnerability.fixed_version else unfixable).append(scored)
    actions = [_action(group) for group in _merged_groups(_by_package(fixable))]
    return FixPlan(actions=tuple(sorted(actions, key=_action_order)), unfixable=tuple(unfixable))


def _by_package(findings: list[ScoredFinding]) -> dict[PackageKey, list[ScoredFinding]]:
    packages: dict[PackageKey, list[ScoredFinding]] = {}
    for scored in findings:
        finding = scored.finding
        component = finding.component
        key = (finding.target, component.ecosystem or "", component.name, component.version)
        packages.setdefault(key, []).append(scored)
    return packages


def _merged_groups(
    packages: dict[PackageKey, list[ScoredFinding]],
) -> list[list[ScoredFinding]]:
    """Merge packages of one target, ecosystem and version that need exactly the same fixes."""
    merged: dict[MergeKey, list[ScoredFinding]] = {}
    for (target, ecosystem, _name, version), group in packages.items():
        fixes = frozenset(
            (s.finding.vulnerability.vuln_id, s.finding.vulnerability.fixed_version or "")
            for s in group
        )
        merged.setdefault((target, ecosystem, version, fixes), []).extend(group)
    return list(merged.values())


def _action(group: list[ScoredFinding]) -> FixAction:
    ranked = tuple(rank(group))
    first = ranked[0].finding
    ecosystem = first.component.ecosystem
    installed = first.component.version
    vuln_ids = tuple(dict.fromkeys(s.finding.vulnerability.vuln_id for s in ranked))
    return FixAction(
        target=first.target,
        ecosystem=ecosystem,
        packages=tuple(sorted({s.finding.component.name for s in ranked})),
        installed_version=installed,
        fixed_version=upgrade_target(
            installed, (s.finding.vulnerability.fixed_version or "" for s in ranked), ecosystem
        ),
        findings=ranked,
        priority=ranked[0].priority,
        vuln_ids=vuln_ids,
        counts=_counts(ranked),
        kev_count=len({s.finding.vulnerability.vuln_id for s in ranked if s.enrichment.in_kev}),
    )


def _counts(ranked: tuple[ScoredFinding, ...]) -> dict[Priority, int]:
    """Distinct vulnerabilities per tier: a CVE in two merged packages counts once."""
    best: dict[str, Priority] = {}
    for scored in ranked:  # ranked, so the first occurrence is the most urgent
        best.setdefault(scored.finding.vulnerability.vuln_id, scored.priority)
    counts = dict.fromkeys(Priority, 0)
    for priority in best.values():
        counts[priority] += 1
    return counts


def _action_order(action: FixAction) -> tuple[int, int, int, int, float, tuple[str, ...], str]:
    """Most urgent tier first; then more KEV entries, more urgent fixes, bigger payoff."""
    epss = [f.enrichment.epss_score for f in action.findings if f.enrichment.epss_score is not None]
    return (
        action.priority.rank,
        -action.kev_count,
        -action.counts[action.priority],
        -len(action.vuln_ids),
        -max(epss) if epss else math.inf,
        action.packages,
        action.target,
    )
