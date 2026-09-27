"""GitHub-flavoured Markdown, e.g. for a pull-request comment or a CI job summary."""

from typing import TextIO

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Report, ScoredFinding
from vulnrank.domain.remediation import FixAction, plan_fixes

HEADER = ("#", "Tier", "ID", "Component", "EPSS", "CVSS", "KEV", "Fix", "Why")
FIX_HEADER = ("#", "Tier", "Upgrade", "Version", "Vulnerabilities", "KEV", "IDs")
LINKED_IDS = 5


class MarkdownReporter:
    def __init__(self, *, fixes: bool = False) -> None:
        self._fixes = fixes

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        out.write(render_fix_plan(report, limit) if self._fixes else render(report, limit))


def render(report: Report, limit: int | None = None) -> str:
    title = ", ".join(report.targets) or "no findings"
    lines = [f"## vulnrank: {_escape(title)}", "", fmt.summary(report), ""]
    if warning := fmt.enrichment_warning(report):
        lines.extend([f"> **{_escape(warning)}**", ""])
    findings = fmt.listed(report, limit)
    if findings:
        lines.append(_row(HEADER))
        lines.append(_row(("---:", *("---" for _ in HEADER[1:]))))
        lines.extend(_row(_cells(rank, s)) for rank, s in enumerate(findings, start=1))
        lines.append("")
    if note := fmt.truncation_note(report, limit):
        lines.extend([f"_{note}_", ""])
    return "\n".join(lines)


def render_fix_plan(report: Report, limit: int | None = None) -> str:
    plan = plan_fixes(report.findings)
    title = ", ".join(report.targets) or "no findings"
    lines = [f"## vulnrank fix plan: {_escape(title)}", "", fmt.fix_plan_summary(plan), ""]
    if warning := fmt.enrichment_warning(report):
        lines.extend([f"> **{_escape(warning)}**", ""])
    actions = fmt.listed_actions(plan, limit)
    if actions:
        lines.append(_row(FIX_HEADER))
        lines.append(_row(("---:", *("---" for _ in FIX_HEADER[1:]))))
        lines.extend(_row(_fix_cells(rank, a)) for rank, a in enumerate(actions, start=1))
        lines.append("")
    if note := fmt.actions_truncation_note(plan, limit):
        lines.extend([f"_{note}_", ""])
    return "\n".join(lines)


def _fix_cells(rank: int, action: FixAction) -> tuple[str, ...]:
    ids = action.vuln_ids
    linked = ", ".join(f"[{i}]({fmt.advisory_url(i)})" for i in ids[:LINKED_IDS])
    more = f" +{len(ids) - LINKED_IDS} more" if len(ids) > LINKED_IDS else ""
    return (
        str(rank),
        f"**{action.priority}**",
        _escape(", ".join(action.packages)),
        _escape(fmt.upgrade(action)),
        fmt.vulnerabilities(action),
        str(action.kev_count),
        linked + more,
    )


def _cells(rank: int, scored: ScoredFinding) -> tuple[str, ...]:
    vuln_id = scored.finding.vulnerability.vuln_id
    return (
        str(rank),
        f"**{scored.priority}**",
        f"[{vuln_id}]({fmt.advisory_url(vuln_id)})",
        _escape(fmt.component(scored)),
        fmt.epss(scored),
        fmt.cvss(scored),
        "**yes**" if scored.enrichment.in_kev else "no",
        _escape(fmt.fix(scored)),
        _escape(fmt.decisive_reasons(scored)),
    )


def _row(cells: tuple[str, ...]) -> str:
    return f"| {' | '.join(cells)} |"


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
