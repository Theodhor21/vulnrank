"""Compare findings with an earlier report, so CI can gate on what changed.

A finding is identified by its image name without tag or digest, its package and its
advisory ID, so `app:1.0` and `app:1.1` compare, and upgrading a package without fixing the
advisory is still the same finding.
"""

from collections.abc import Iterable

from vulnrank.domain.models import (
    Change,
    ChangeState,
    DomainModel,
    Finding,
    Priority,
    ScoredFinding,
)
from vulnrank.domain.targets import image_repository

__all__ = [
    "Baseline",
    "BaselineComparison",
    "BaselineKey",
    "Change",
    "ChangeState",
    "baseline_key",
    "compare_to_baseline",
]

BaselineKey = tuple[str, str, str]  # image repository, package name, advisory ID


class Baseline(DomainModel):
    priorities: dict[BaselineKey, Priority]
    complete: bool = True  # False when the report was cut by --top


class BaselineComparison(DomainModel):
    findings: tuple[ScoredFinding, ...]
    resolved: int  # in the baseline, gone now


def baseline_key(finding: Finding) -> BaselineKey:
    return (
        image_repository(finding.target),
        finding.component.name,
        finding.vulnerability.vuln_id,
    )


def compare_to_baseline(
    findings: Iterable[ScoredFinding], baseline: Baseline
) -> BaselineComparison:
    compared = tuple(
        scored.model_copy(update={"change": _change(scored, baseline)}) for scored in findings
    )
    current = {baseline_key(scored.finding) for scored in compared}
    resolved = sum(1 for key in baseline.priorities if key not in current)
    return BaselineComparison(findings=compared, resolved=resolved)


def _change(scored: ScoredFinding, baseline: Baseline) -> Change:
    previous = baseline.priorities.get(baseline_key(scored.finding))
    if previous is None:
        return Change(state=ChangeState.NEW)
    if scored.priority.rank < previous.rank:
        return Change(state=ChangeState.ESCALATED, previous=previous)
    if scored.priority.rank > previous.rank:
        return Change(state=ChangeState.IMPROVED, previous=previous)
    return Change(state=ChangeState.UNCHANGED, previous=previous)
