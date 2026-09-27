"""Display helpers shared by the human-readable reporters."""

from vulnrank.domain.models import FixStatus, Priority, Report, ScoredFinding

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
    return (
        f"{counts} ({len(report.findings)} unique findings from {report.scanned} records{extras})"
    )


def enrichment_warning(report: Report) -> str | None:
    if not report.enrichment_issues:
        return None
    return "Warning: enrichment incomplete: " + "; ".join(report.enrichment_issues)


def listed(report: Report, limit: int | None) -> tuple[ScoredFinding, ...]:
    return report.findings if limit is None else report.findings[:limit]


def truncation_note(report: Report, limit: int | None) -> str | None:
    total = len(report.findings)
    hidden = total - len(listed(report, limit))
    if hidden == 0:
        return None
    return f"Showing the top {limit} of {total}; {hidden} more not shown."
