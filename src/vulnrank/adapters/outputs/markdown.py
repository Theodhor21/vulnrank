"""GitHub-flavoured Markdown, e.g. for a pull-request comment or a CI job summary."""

from typing import TextIO

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Report, ScoredFinding
from vulnrank.domain.remediation import FixAction, FixPlan, no_fix_status, plan_fixes

HEADER = ("#", "Tier", "ID", "Component", "EPSS", "CVSS", "KEV", "Fix", "Why")
UNFIXABLE_HEADER = ("Tier", "ID", "Component", "Status")
LINKED_IDS = 5


class MarkdownReporter:
    def __init__(self, *, fixes: bool = False) -> None:
        self._fixes = fixes

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        out.write(render_fix_plan(report, limit) if self._fixes else render(report, limit))


def render(report: Report, limit: int | None = None) -> str:
    lines = _heading(report, "vulnrank", fmt.summary(report))
    if since := fmt.baseline_summary(report):
        lines[3:3] = ["", since]  # right under the summary line
    compared = report.baseline_resolved is not None
    header = (*HEADER[:2], *(["Change"] if compared else []), *HEADER[2:])
    findings = fmt.listed(report.findings, limit)
    rows = [_cells(rank, s, compared=compared) for rank, s in enumerate(findings, start=1)]
    lines += _table(header, rows)
    if note := fmt.truncation_note(len(report.findings), limit):
        lines.extend([f"_{note}_", ""])
    return "\n".join(lines)


def render_fix_plan(report: Report, limit: int | None = None) -> str:
    plan = plan_fixes(report.findings)
    lines = _heading(report, "vulnrank fix plan", fmt.fix_plan_summary(plan))
    show_target = len(report.targets) > 1
    header = ("#", "Tier", *(["Target"] if show_target else []), "Upgrade", "Version")
    header += ("Vulnerabilities", "KEV", "IDs")
    actions = fmt.listed(plan.actions, limit)
    rows = [_fix_cells(rank, a, show_target=show_target) for rank, a in enumerate(actions, 1)]
    lines += _table(header, rows)
    if note := fmt.truncation_note(len(plan.actions), limit, "upgrades"):
        lines.extend([f"_{note}_", ""])
    lines += _unfixable(plan)
    return "\n".join(lines)


def _heading(report: Report, title: str, summary: str) -> list[str]:
    targets = ", ".join(report.targets) or "no findings"
    lines = [f"## {title}: {_escape(targets)}", "", summary, ""]
    if warning := fmt.enrichment_warning(report):
        lines.extend([f"> **{_escape(warning)}**", ""])
    return lines


def _table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    if not rows:
        return []
    align = ("---:" if header[0] == "#" else "---", *("---" for _ in header[1:]))
    return [_row(header), _row(align), *(_row(cells) for cells in rows), ""]


def _unfixable(plan: FixPlan) -> list[str]:
    shown = fmt.unfixable_listed(plan)
    if not shown:
        return []
    lines = ["**Without a fix** (most urgent first)", ""]
    lines += _table(UNFIXABLE_HEADER, [_unfixable_cells(s) for s in shown])
    if note := fmt.unfixable_more_note(plan):
        lines.extend([f"_{note}_", ""])
    return lines


def _link(vuln_id: str) -> str:
    return f"[{vuln_id}]({fmt.advisory_url(vuln_id)})"


def _fix_cells(rank: int, action: FixAction, *, show_target: bool) -> tuple[str, ...]:
    return (
        str(rank),
        f"**{action.priority}**",
        *([_escape(action.target)] if show_target else []),
        _escape(", ".join(action.packages)),
        _escape(fmt.upgrade(action)),
        fmt.vulnerabilities(action),
        str(action.kev_count),
        fmt.shortened(action.vuln_ids, LINKED_IDS, _link),
    )


def _unfixable_cells(scored: ScoredFinding) -> tuple[str, ...]:
    return (
        f"**{scored.priority}**",
        _link(scored.finding.vulnerability.vuln_id),
        _escape(fmt.component(scored)),
        no_fix_status(scored),
    )


def _cells(rank: int, scored: ScoredFinding, *, compared: bool) -> tuple[str, ...]:
    return (
        str(rank),
        f"**{scored.priority}**",
        *([fmt.change(scored)] if compared else []),
        _link(scored.finding.vulnerability.vuln_id),
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
