"""Turn ranked findings into a fix plan: "upgrade X to version Y fixes N vulnerabilities".

Teams file tickets per upgrade, not per CVE. Findings with a fixed version are grouped per
package (target, name, installed version). Packages from one source that need exactly the
same fixes, such as Debian's `openssl` and `libssl1.1`, become one action.

Package versions are compared in natural order (numbers as numbers), which handles the
common Debian, Alpine, Python and npm version strings but is not a full implementation of
any one ecosystem's rules.
"""

import math
import re
from collections.abc import Iterable

from vulnrank.domain.models import DomainModel, Priority, ScoredFinding
from vulnrank.domain.scoring import rank

_NUMBERS = re.compile(r"(\d+)")

VersionKey = tuple[tuple[int, str], ...]


def version_key(version: str) -> VersionKey:
    """`7.88.1-10+deb12u9` < `7.88.1-10+deb12u10`: digit runs compare as numbers."""
    return tuple(
        (int(part), "") if index % 2 else (0, part)
        for index, part in enumerate(_NUMBERS.split(version))
    )


class FixAction(DomainModel):
    target: str
    packages: tuple[str, ...]
    installed_version: str
    fixed_version: str
    findings: tuple[ScoredFinding, ...]

    @property
    def vuln_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(f.finding.vulnerability.vuln_id for f in self.findings))

    @property
    def priority(self) -> Priority:
        return min((f.priority for f in self.findings), key=lambda p: p.rank)

    @property
    def counts(self) -> dict[Priority, int]:
        """Distinct vulnerabilities per tier (a CVE in two merged packages counts once)."""
        best: dict[str, Priority] = {}
        for scored in self.findings:  # ranked, so the first occurrence is the most urgent
            best.setdefault(scored.finding.vulnerability.vuln_id, scored.priority)
        counts = dict.fromkeys(Priority, 0)
        for priority in best.values():
            counts[priority] += 1
        return counts

    @property
    def kev_count(self) -> int:
        return len({f.finding.vulnerability.vuln_id for f in self.findings if f.enrichment.in_kev})


class FixPlan(DomainModel):
    actions: tuple[FixAction, ...]
    unfixable: tuple[ScoredFinding, ...]

    @property
    def fixable_findings(self) -> int:
        return sum(len(action.findings) for action in self.actions)


PackageKey = tuple[str, str, str]  # target, package name, installed version
MergeKey = tuple[str, str, frozenset[tuple[str, str]]]  # target, version, (vuln, fix) pairs


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
        key = (finding.target, finding.component.name, finding.component.version)
        packages.setdefault(key, []).append(scored)
    return packages


def _merged_groups(
    packages: dict[PackageKey, list[ScoredFinding]],
) -> list[list[ScoredFinding]]:
    """Merge packages of one target and version that need exactly the same fixes."""
    merged: dict[MergeKey, list[ScoredFinding]] = {}
    for (target, _name, version), group in packages.items():
        fixes = frozenset(
            (s.finding.vulnerability.vuln_id, s.finding.vulnerability.fixed_version or "")
            for s in group
        )
        merged.setdefault((target, version, fixes), []).extend(group)
    return list(merged.values())


def _action(group: list[ScoredFinding]) -> FixAction:
    first = group[0].finding
    fixed_versions = {s.finding.vulnerability.fixed_version or "" for s in group}
    return FixAction(
        target=first.target,
        packages=tuple(sorted({s.finding.component.name for s in group})),
        installed_version=first.component.version,
        fixed_version=max(fixed_versions, key=version_key),
        findings=tuple(rank(group)),
    )


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
