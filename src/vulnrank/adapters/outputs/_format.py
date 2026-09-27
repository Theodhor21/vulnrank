"""Display helpers shared by the human-readable reporters."""

from collections import Counter
from collections.abc import Callable

from vulnrank.domain.models import ChangeState, FixStatus, Priority, Report, ScoredFinding
from vulnrank.domain.remediation import FixAction, FixPlan

NOT_AVAILABLE = "-"

NO_FIX_LABELS = {
    FixStatus.WILL_NOT_FIX: "no fix (will not fix)",
    FixStatus.FIX_DEFERRED: "no fix (deferred)",
    FixStatus.END_OF_LIFE: "no fix (end-of-life)",
}

PRIORITY_STYLES = {
    Priority.P1: "bold white on red",
    Priority.P2: "bold red",
    Priority.P3: "yellow",
    Priority.P4: "dim",
}


def epss(scored: ScoredFinding) -> str:
    value = scored.enrichment.epss_score
    if value is None:
        return NOT_AVAILABLE
    # Most EPSS scores are tiny; keep a significant digit instead of printing 0.0%.
    return f"{value:.1%}" if value >= 0.01 else f"{value:.2%}"


def cvss(scored: ScoredFinding) -> str:
    value = scored.finding.vulnerability.cvss_score
    return NOT_AVAILABLE if value is None else f"{value:.1f}"


def component(scored: ScoredFinding) -> str:
    return f"{scored.finding.component.name} {scored.finding.component.version}".strip()


def fix(scored: ScoredFinding) -> str:
    vulnerability = scored.finding.vulnerability
    if vulnerability.fixed_version:
        return vulnerability.fixed_version
    status = vulnerability.status
    return NO_FIX_LABELS.get(status, "no fix") if status else "no fix"


def advisory_url(vuln_id: str) -> str:
    """NVD for CVEs, GitHub for GHSA, OSV for everything else."""
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


def decisive_reasons(scored: ScoredFinding) -> str:
    """Only the reasons that set the tier; context such as the fix has its own column."""
    return "; ".join(reason.text for reason in scored.reasons if reason.tier is not None)


def summary(report: Report) -> str:
    counts = " · ".join(f"{priority}: {count}" for priority, count in report.counts.items())
    extras = ""
    if report.duplicates_removed:
        extras += f", {report.duplicates_removed} duplicates removed"
    if report.skipped:
        extras += f", {report.skipped} malformed records skipped"
    if report.suppressed:
        extras += f", {len(report.suppressed)} suppressed"
    return (
        f"{counts} ({len(report.findings)} unique findings from {report.scanned} records{extras})"
    )


def baseline_counts(report: Report) -> dict[str, int] | None:
    if report.baseline_resolved is None:
        return None
    states = Counter(s.change.state for s in report.findings if s.change is not None)
    counts = {str(state): states[state] for state in ChangeState}
    return {**counts, "resolved": report.baseline_resolved}


def baseline_summary(report: Report) -> str | None:
    """`Since baseline: 1 new, 1 escalated, 0 improved, 2 resolved`"""
    counts = baseline_counts(report)
    if counts is None:
        return None
    shown = ("new", "escalated", "improved", "resolved")
    return "Since baseline: " + ", ".join(f"{counts[key]} {key}" for key in shown)


def change(scored: ScoredFinding) -> str:
    """`new`, `↑ from P3`, `↓ from P1`, or nothing when unchanged."""
    if scored.change is None or scored.change.state is ChangeState.UNCHANGED:
        return ""
    if scored.change.state is ChangeState.NEW:
        return "new"
    arrow = "↑" if scored.change.state is ChangeState.ESCALATED else "↓"
    return f"{arrow} from {scored.change.previous}"


def enrichment_warning(report: Report) -> str | None:
    if not report.enrichment_issues:
        return None
    return "Warning: enrichment incomplete: " + "; ".join(report.enrichment_issues)


def listed[T](items: tuple[T, ...], limit: int | None) -> tuple[T, ...]:
    return items if limit is None else items[:limit]


def truncation_note(total: int, limit: int | None, noun: str = "") -> str | None:
    """`Showing the top 20 of 415 upgrades; 395 more not shown.` or None if nothing is hidden."""
    shown = total if limit is None else min(limit, total)
    if shown == total:
        return None
    what = f" {noun}" if noun else ""
    return f"Showing the top {shown} of {total}{what}; {total - shown} more not shown."


def shortened[T](items: tuple[T, ...], shown: int, render: Callable[[T], str] = str) -> str:
    """`a, b, c +4 more`"""
    more = f" +{len(items) - shown} more" if len(items) > shown else ""
    return ", ".join(render(item) for item in items[:shown]) + more


# --- Fix plan ----------------------------------------------------------------------------------

UNFIXABLE_SHOWN = 5


def _plural(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def fix_plan_summary(plan: FixPlan) -> str:
    """`37 upgrades cover 337 findings; 87 findings have no fix (44 not yet fixed, ...)`"""
    upgrades, covered, open_ = len(plan.actions), plan.fixable_findings, len(plan.unfixable)
    breakdown = ", ".join(f"{count} {status}" for status, count in plan.unfixable_by_status.items())
    return (
        f"{upgrades} {_plural(upgrades, 'upgrade covers', 'upgrades cover')} "
        f"{covered} {_plural(covered, 'finding', 'findings')}; "
        f"{open_} {_plural(open_, 'finding has', 'findings have')} no fix"
        + (f" ({breakdown})" if breakdown else "")
    )


def upgrade(action: FixAction) -> str:
    return f"{action.installed_version} → {action.fixed_version}"


def vulnerabilities(action: FixAction) -> str:
    """`2 (P1: 1, P2: 1)`: distinct vulnerabilities, broken down by tier."""
    breakdown = ", ".join(f"{p}: {n}" for p, n in action.counts.items() if n)
    return f"{len(action.vuln_ids)} ({breakdown})"


def unfixable_listed(plan: FixPlan) -> tuple[ScoredFinding, ...]:
    """The most urgent findings without a fix (the plan keeps them in ranked order)."""
    return listed(plan.unfixable, UNFIXABLE_SHOWN)


def unfixable_more_note(plan: FixPlan) -> str | None:
    hidden = len(plan.unfixable) - len(unfixable_listed(plan))
    return f"{hidden} more without a fix; see `--view findings`." if hidden else None
