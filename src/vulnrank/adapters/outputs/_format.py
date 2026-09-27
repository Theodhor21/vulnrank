"""Display helpers shared by the human-readable reporters."""

from vulnrank.domain.models import Priority, Report, ScoredFinding

NOT_AVAILABLE = "-"

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
    return scored.finding.vulnerability.fixed_version or "no fix"


def decisive_reasons(scored: ScoredFinding) -> str:
    """Only the reasons that set the tier; context such as the fix has its own column."""
    return "; ".join(reason.text for reason in scored.reasons if reason.tier is not None)


def summary(report: Report) -> str:
    counts = " · ".join(f"{priority}: {count}" for priority, count in report.counts.items())
    removed = report.duplicates_removed
    duplicates = f", {removed} duplicates removed" if removed else ""
    return (
        f"{counts} ({len(report.findings)} unique findings "
        f"from {report.scanned} scanned{duplicates})"
    )


def listed(report: Report, limit: int | None) -> tuple[ScoredFinding, ...]:
    return report.findings if limit is None else report.findings[:limit]


def truncation_note(report: Report, limit: int | None) -> str | None:
    total = len(report.findings)
    hidden = total - len(listed(report, limit))
    if hidden == 0:
        return None
    return f"Showing the top {limit} of {total}; {hidden} more not shown."
