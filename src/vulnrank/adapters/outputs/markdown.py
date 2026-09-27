"""GitHub-flavoured Markdown, e.g. for a pull-request comment or a CI job summary."""

from typing import TextIO

from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import Report, ScoredFinding

HEADER = ("#", "Tier", "CVE", "Component", "EPSS", "CVSS", "KEV", "Fix", "Why")
NVD_URL = "https://nvd.nist.gov/vuln/detail/"


class MarkdownReporter:
    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        out.write(render(report, limit))


def render(report: Report, limit: int | None = None) -> str:
    title = ", ".join(report.targets) or "no findings"
    lines = [f"## vulnrank: {_escape(title)}", "", fmt.summary(report), ""]
    findings = fmt.listed(report, limit)
    if findings:
        lines.append(_row(HEADER))
        lines.append(_row(("---:", *("---" for _ in HEADER[1:]))))
        lines.extend(_row(_cells(rank, s)) for rank, s in enumerate(findings, start=1))
        lines.append("")
    if note := fmt.truncation_note(report, limit):
        lines.extend([f"_{note}_", ""])
    return "\n".join(lines)


def _cells(rank: int, scored: ScoredFinding) -> tuple[str, ...]:
    cve = scored.finding.vulnerability.cve_id
    return (
        str(rank),
        f"**{scored.priority}**",
        f"[{cve}]({NVD_URL}{cve})",
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
