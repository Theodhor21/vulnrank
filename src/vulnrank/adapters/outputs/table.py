"""A terminal table rendered with rich."""

from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Report, ScoredFinding
from vulnrank.domain.remediation import FixAction, FixPlan, plan_fixes

# Below this width, secondary columns are dropped so the reasons stay readable.
COMPACT_BELOW_COLUMNS = 100


class TableReporter:
    def __init__(self, *, width: int | None = None, fixes: bool = False) -> None:
        self._width = width
        self._fixes = fixes

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        console = Console(file=out, width=self._width, highlight=False)
        if self._fixes:
            plan = plan_fixes(report.findings)
            if plan.actions:
                console.print(_fix_table(report, plan, limit))
            if note := fmt.actions_truncation_note(plan, limit):
                console.print(note, style="dim")
            console.print(fmt.fix_plan_summary(plan))
        else:
            compact = console.width < COMPACT_BELOW_COLUMNS
            console.print(_table(report, limit, compact=compact))
            if note := fmt.truncation_note(report, limit):
                console.print(note, style="dim")
            console.print(fmt.summary(report))
        if warning := fmt.enrichment_warning(report):
            console.print(warning, style="bold yellow")


def _title(report: Report, heading: str) -> str:
    targets = report.targets
    return f"{heading}: {targets[0]}" if len(targets) == 1 else heading


def _fix_table(report: Report, plan: FixPlan, limit: int | None) -> Table:
    show_target = len(report.targets) > 1
    table = Table(title=_title(report, "vulnrank fix plan"), title_justify="left")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Tier", no_wrap=True)
    if show_target:
        table.add_column("Target", overflow="fold")
    table.add_column("Upgrade", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Vulnerabilities", no_wrap=True)
    table.add_column("KEV", justify="right", no_wrap=True)
    table.add_column("IDs", ratio=1, overflow="fold")
    for rank, action in enumerate(fmt.listed_actions(plan, limit), start=1):
        table.add_row(*_fix_cells(rank, action, show_target=show_target))
    return table


def _fix_cells(rank: int, action: FixAction, *, show_target: bool) -> list[str | Text]:
    return [
        str(rank),
        Text(f" {action.priority} ", style=fmt.PRIORITY_STYLES[action.priority]),
        *([action.target] if show_target else []),
        ", ".join(action.packages),
        fmt.upgrade(action),
        fmt.vulnerabilities(action),
        str(action.kev_count),
        fmt.shortened_ids(action),
    ]


def _table(report: Report, limit: int | None, *, compact: bool) -> Table:
    show_target = len(report.targets) > 1 and not compact
    table = Table(title=_title(report, "vulnrank"), title_justify="left")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Tier", no_wrap=True)
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
    for rank, scored in enumerate(fmt.listed(report, limit), start=1):
        table.add_row(*_cells(rank, scored, show_target=show_target, compact=compact))
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
        Text(f" {scored.priority} ", style=fmt.PRIORITY_STYLES[scored.priority]),
        scored.finding.vulnerability.vuln_id,
        fmt.component(scored),
        *([scored.finding.target] if show_target else []),
        *([] if compact else details),
        fmt.decisive_reasons(scored),
    ]
