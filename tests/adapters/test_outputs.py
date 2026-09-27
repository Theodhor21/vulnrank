import io
import json
from datetime import date

import pytest

from tests.builders import make_asset, make_enrichment, make_finding
from vulnrank.adapters.outputs.json_report import JsonReporter
from vulnrank.adapters.outputs.markdown import MarkdownReporter
from vulnrank.adapters.outputs.table import TableReporter
from vulnrank.domain.models import Criticality, Report, ScoredFinding
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import rank, score
from vulnrank.ports.reporting import Reporter


def _scored(
    *,
    cve: str = "CVE-2024-0001",
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool = False,
    kev_date: date | None = None,
    fixed: str | None = None,
    component: str = "openssl",
    target: str = "app:1.0",
) -> ScoredFinding:
    return score(
        make_finding(
            cve_id=cve, cvss=cvss, fixed_version=fixed, component=component, target=target
        ),
        make_enrichment(epss=epss, in_kev=kev, kev_date_added=kev_date),
        make_asset(criticality=Criticality.HIGH, target=target),
        ScoringPolicy(),
    )


REPORT = Report(
    findings=tuple(
        rank(
            [
                _scored(cve="CVE-2024-0001", kev=True, kev_date=date(2024, 5, 1), fixed="1.1"),
                _scored(cve="CVE-2024-0002", epss=0.0004, cvss=9.8, component="a|b"),
                _scored(cve="CVE-2024-0003", cvss=5.0),
            ]
        )
    ),
    scanned=4,
    duplicates_removed=1,
)


def _render(reporter: Reporter, report: Report = REPORT, limit: int | None = None) -> str:
    out = io.StringIO()
    reporter.write(report, out, limit=limit)
    return out.getvalue()


# --- JSON ----------------------------------------------------------------------------------


def test_json_document_structure() -> None:
    document = json.loads(_render(JsonReporter()))
    assert document["schema_version"] == 1
    assert document["summary"] == {
        "scanned": 4,
        "duplicates_removed": 1,
        "unique_findings": 3,
        "listed": 3,
        "by_priority": {"P1": 1, "P2": 1, "P3": 0, "P4": 1},
        "targets": ["app:1.0"],
    }
    first = document["findings"][0]
    assert first["rank"] == 1
    assert first["priority"] == "P1"
    assert first["cve"] == "CVE-2024-0001"
    assert first["in_kev"] is True
    assert first["kev_date_added"] == "2024-05-01"
    assert first["fixed_version"] == "1.1"
    assert first["component"]["name"] == "openssl"
    assert first["asset"] == {"criticality": "high", "internet_exposed": False}
    assert first["reasons"][0] == {"text": "in CISA KEV (added 2024-05-01)", "decisive": True}
    assert first["reasons"][-1]["decisive"] is False


def test_json_limit_lists_fewer_findings_but_keeps_the_full_summary() -> None:
    document = json.loads(_render(JsonReporter(), limit=1))
    assert len(document["findings"]) == 1
    assert document["summary"]["unique_findings"] == 3
    assert document["summary"]["listed"] == 1


# --- Markdown --------------------------------------------------------------------------------


def test_markdown_table() -> None:
    text = _render(MarkdownReporter())
    lines = text.splitlines()
    assert lines[0] == "## vulnrank: app:1.0"
    assert (
        lines[2]
        == "P1: 1 · P2: 1 · P3: 0 · P4: 1 (3 unique findings from 4 scanned, 1 duplicates removed)"
    )
    assert lines[4].startswith("| # | Tier | CVE |")
    assert (
        "| 1 | **P1** | [CVE-2024-0001](https://nvd.nist.gov/vuln/detail/CVE-2024-0001) |" in text
    )
    assert "a\\|b" in text  # pipes are escaped so the table does not break
    assert "0.04%" in text  # tiny EPSS values keep a meaningful digit


def test_markdown_notes_truncation() -> None:
    assert "_Showing the top 2 of 3; 1 more not shown._" in _render(MarkdownReporter(), limit=2)


def test_markdown_for_an_empty_report() -> None:
    empty = Report(findings=(), scanned=0, duplicates_removed=0)
    assert _render(MarkdownReporter(), empty).startswith("## vulnrank: no findings")


# --- Table -----------------------------------------------------------------------------------


def test_table_lists_findings_and_summary() -> None:
    text = _render(TableReporter(width=200))
    assert "vulnrank: app:1.0" in text
    assert text.index("CVE-2024-0001") < text.index("CVE-2024-0002") < text.index("CVE-2024-0003")
    assert "in CISA KEV (added 2024-05-01)" in text
    assert "P1: 1 · P2: 1 · P3: 0 · P4: 1" in text
    assert "Target" not in text


def test_table_shows_targets_when_there_are_several() -> None:
    report = Report(
        findings=(_scored(target="api:2"), _scored(target="web:1")),
        scanned=2,
        duplicates_removed=0,
    )
    text = _render(TableReporter(width=200), report)
    assert "Target" in text
    assert "api:2" in text


@pytest.mark.parametrize("limit", [1, 2])
def test_table_notes_truncation(limit: int) -> None:
    text = _render(TableReporter(width=200), limit=limit)
    assert f"Showing the top {limit} of 3" in text
    assert "CVE-2024-0003" not in text
