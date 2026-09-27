"""A terminal table rendered with rich."""

from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Priority, Report, ScoredFinding
from vulnrank.domain.remediation import FixAction, FixPlan, no_fix_status, plan_fixes

# Below this width, secondary columns are dropped so the reasons stay readable.
COMPACT_BELOW_COLUMNS = 100
SHOWN_IDS = 3


class TableReporter:
    def __init__(self, *, width: int | None = None, fixes: bool = False) -> None:
        self._width = width
        self._fixes = fixes

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        console = Console(file=out, width=self._width, highlight=False)
        compact = console.width < COMPACT_BELOW_COLUMNS
        if self._fixes:
            plan = plan_fixes(report.findings)
            if plan.actions:
                console.print(_fix_table(report, plan, limit, compact=compact))
            if note := fmt.truncation_note(len(plan.actions), limit, "upgrades"):
                console.print(note, style="dim")
            console.print(fmt.fix_plan_summary(plan))
            if unfixable := fmt.unfixable_listed(plan):
                console.print(_unfixable_table(unfixable))
                if more := fmt.unfixable_more_note(plan):
                    console.print(more, style="dim")
        else:
            console.print(_table(report, limit, compact=compact))
            if note := fmt.truncation_note(len(report.findings), limit):
                console.print(note, style="dim")
            console.print(fmt.summary(report))
            if since := fmt.baseline_summary(report):
                console.print(since)
        if warning := fmt.enrichment_warning(report):
            console.print(warning, style="bold yellow")


def _title(report: Report, heading: str) -> str:
    targets = report.targets
    return f"{heading}: {targets[0]}" if len(targets) == 1 else heading


def _tier(priority: Priority) -> Text:
    return Text(f" {priority} ", style=fmt.PRIORITY_STYLES[priority])


def _fix_table(report: Report, plan: FixPlan, limit: int | None, *, compact: bool) -> Table:
    show_target = len(report.targets) > 1 and not compact
    table = Table(title=_title(report, "vulnrank fix plan"), title_justify="left")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Tier", no_wrap=True)
    if show_target:
        table.add_column("Target", overflow="fold")
    table.add_column("Upgrade", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Vulnerabilities", overflow="fold")
    if not compact:
        table.add_column("KEV", justify="right", no_wrap=True)
        table.add_column("IDs", ratio=1, overflow="fold")
    for rank, action in enumerate(fmt.listed(plan.actions, limit), start=1):
        table.add_row(*_fix_cells(rank, action, show_target=show_target, compact=compact))
    return table


def _fix_cells(
    rank: int, action: FixAction, *, show_target: bool, compact: bool
) -> list[str | Text]:
    details = [str(action.kev_count), fmt.shortened(action.vuln_ids, SHOWN_IDS)]
    return [
        str(rank),
        _tier(action.priority),
        *([action.target] if show_target else []),
        ", ".join(action.packages),
        fmt.upgrade(action),
        fmt.vulnerabilities(action),
        *([] if compact else details),
    ]


def _unfixable_table(unfixable: tuple[ScoredFinding, ...]) -> Table:
    table = Table(title="Without a fix (most urgent first)", title_justify="left")
    for name in ("Tier", "ID", "Component", "Status"):
        table.add_column(name, overflow="fold")
    for scored in unfixable:
        table.add_row(
            _tier(scored.priority),
            scored.finding.vulnerability.vuln_id,
            fmt.component(scored),
            no_fix_status(scored),
        )
    return table


def _table(report: Report, limit: int | None, *, compact: bool) -> Table:
    show_target = len(report.targets) > 1 and not compact
    table = Table(title=_title(report, "vulnrank"), title_justify="left")
    compared = report.baseline_resolved is not None
    table.add_column("#", justify="right", style="dim")
    table.add_column("Tier", no_wrap=True)
    if compared:
        table.add_column("Change", no_wrap=True)
    table.add_column("ID", no_wrap=True)
    table.add_column("Component", overflow="fold")
    if show_target:
        table.add_column("Target", overflow="fold")
    if not compact:
        for name in ("EPSS", "CVSS"):
            table.add_column(name, justify="right", no_wrap=True)
        table.add_column("KEV", no_wrap=True)
        table.add_column("Fix", overflow="fold")
    table.add_column("Why", ratio=1, overflow="fold")
    for rank, scored in enumerate(fmt.listed(report.findings, limit), start=1):
        cells = _cells(rank, scored, show_target=show_target, compact=compact)
        if compared:
            cells.insert(2, fmt.change(scored))
        table.add_row(*cells)
    return table


def _cells(
    rank: int, scored: ScoredFinding, *, show_target: bool, compact: bool
) -> list[str | Text]:
    in_kev = scored.enrichment.in_kev
    details: list[str | Text] = [
        fmt.epss(scored),
        fmt.cvss(scored),
        Text("yes" if in_kev else "no", style="bold red" if in_kev else ""),
        fmt.fix(scored),
    ]
    return [
        str(rank),
        _tier(scored.priority),
        scored.finding.vulnerability.vuln_id,
        fmt.component(scored),
        *([scored.finding.target] if show_target else []),
        *([] if compact else details),
        fmt.decisive_reasons(scored),
    ]
