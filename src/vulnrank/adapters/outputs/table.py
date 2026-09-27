"""A terminal table rendered with rich."""

from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Report, ScoredFinding

# Below this width, secondary columns are dropped so the reasons stay readable.
COMPACT_BELOW_COLUMNS = 100


class TableReporter:
    def __init__(self, *, width: int | None = None) -> None:
        self._width = width

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        console = Console(file=out, width=self._width, highlight=False)
        compact = console.width < COMPACT_BELOW_COLUMNS
        console.print(_table(report, limit, compact=compact))
        if note := fmt.truncation_note(report, limit):
            console.print(note, style="dim")
        console.print(fmt.summary(report))
        if warning := fmt.enrichment_warning(report):
            console.print(warning, style="bold yellow")


def _table(report: Report, limit: int | None, *, compact: bool) -> Table:
    targets = report.targets
    show_target = len(targets) > 1 and not compact
    title = f"vulnrank: {targets[0]}" if len(targets) == 1 else "vulnrank"
    table = Table(title=title, title_justify="left")
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
