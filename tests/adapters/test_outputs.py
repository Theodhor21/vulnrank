import io
import json
from datetime import date

import pytest

from tests.builders import make_asset, make_enrichment, make_finding
from vulnrank.adapters.outputs._format import advisory_url, fix
from vulnrank.adapters.outputs.json_report import JsonReporter
from vulnrank.adapters.outputs.markdown import MarkdownReporter
from vulnrank.adapters.outputs.table import TableReporter
from vulnrank.domain.models import Criticality, FixStatus, Report, ScoredFinding, Suppressed
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
    status: FixStatus | None = None,
) -> ScoredFinding:
    return score(
        make_finding(
            vuln_id=cve,
            cvss=cvss,
            fixed_version=fixed,
            component=component,
            target=target,
            status=status,
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
    assert document["schema_version"] == 2
    assert document["summary"] == {
        "scanned": 4,
        "skipped": 0,
        "duplicates_removed": 1,
        "unique_findings": 3,
        "listed": 3,
        "by_priority": {"P1": 1, "P2": 1, "P3": 0, "P4": 1},
        "targets": ["app:1.0"],
        "enrichment_issues": [],
        "suppressed": 0,
    }
    first = document["findings"][0]
    assert first["rank"] == 1
    assert first["priority"] == "P1"
    assert first["id"] == "CVE-2024-0001"
    assert first["fix_status"] is None
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
        == "P1: 1 · P2: 1 · P3: 0 · P4: 1 (3 unique findings from 4 records, 1 duplicates removed)"
    )
    assert lines[4].startswith("| # | Tier | ID |")
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


# --- Shared formatting -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vuln_id", "url"),
    [
        ("CVE-2024-0001", "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"),
        ("GHSA-jfh8-c2jp-5v3q", "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"),
        ("PYSEC-2021-19", "https://osv.dev/vulnerability/PYSEC-2021-19"),
    ],
)
def test_advisory_url(vuln_id: str, url: str) -> None:
    assert advisory_url(vuln_id) == url


@pytest.mark.parametrize(
    ("fixed", "status", "text"),
    [
        ("1.1", FixStatus.FIXED, "1.1"),
        (None, None, "no fix"),
        (None, FixStatus.WILL_NOT_FIX, "no fix (will not fix)"),
        (None, FixStatus.FIX_DEFERRED, "no fix (deferred)"),
        (None, FixStatus.END_OF_LIFE, "no fix (end-of-life)"),
    ],
)
def test_fix_column_explains_why_there_is_no_fix(
    fixed: str | None, status: FixStatus | None, text: str
) -> None:
    assert fix(_scored(fixed=fixed, status=status)) == text


SKIPPED_WITH_ISSUES = Report(
    findings=REPORT.findings,
    scanned=6,
    skipped=2,
    duplicates_removed=1,
    enrichment_issues=("offline: no cached KEV catalog",),
)


def test_summary_mentions_skipped_records() -> None:
    assert (
        "(3 unique findings from 6 records, 1 duplicates removed, 2 malformed records skipped)"
        in _render(MarkdownReporter(), SKIPPED_WITH_ISSUES)
    )


@pytest.mark.parametrize(
    "reporter", [MarkdownReporter(), TableReporter(width=200)], ids=["markdown", "table"]
)
def test_human_readable_reports_warn_about_incomplete_enrichment(reporter: Reporter) -> None:
    text = _render(reporter, SKIPPED_WITH_ISSUES)
    assert "Warning: enrichment incomplete: offline: no cached KEV catalog" in text


def test_json_lists_skipped_records_and_enrichment_issues() -> None:
    summary = json.loads(_render(JsonReporter(), SKIPPED_WITH_ISSUES))["summary"]
    assert summary["skipped"] == 2
    assert summary["enrichment_issues"] == ["offline: no cached KEV catalog"]


def test_markdown_links_non_cve_advisories_to_their_source() -> None:
    report = Report(findings=(_scored(cve="GHSA-jfh8-c2jp-5v3q"),), scanned=1, duplicates_removed=0)
    text = _render(MarkdownReporter(), report)
    assert "[GHSA-jfh8-c2jp-5v3q](https://github.com/advisories/GHSA-jfh8-c2jp-5v3q)" in text


def test_narrow_table_keeps_the_reasons_readable() -> None:
    """At 80 columns, drop secondary columns instead of truncating the reasons."""
    text = _render(TableReporter(width=80))
    assert "…" not in text
    assert "EPSS" not in text
    assert "Fix" not in text
    assert "KEV" in text  # the reason column still says why
    assert text.index("CVE-2024-0001") < text.index("CVE-2024-0002")


# --- Fix plan: "upgrade X to fix N" ------------------------------------------------------------

FIX_REPORT = Report(
    findings=tuple(
        rank(
            [
                _scored(cve="CVE-2024-0001", kev=True, fixed="1.1", component="openssl"),
                _scored(cve="CVE-2024-0001", kev=True, fixed="1.1", component="libssl1.1"),
                _scored(cve="CVE-2024-0002", cvss=9.8, fixed="1.2", component="openssl"),
                _scored(cve="CVE-2024-0002", cvss=9.8, fixed="1.2", component="libssl1.1"),
                _scored(cve="CVE-2024-0003", cvss=5.0, component="zlib"),
            ]
        )
    ),
    scanned=5,
    duplicates_removed=0,
)


def test_json_always_includes_the_fix_plan() -> None:
    plan = json.loads(_render(JsonReporter(), FIX_REPORT))["fix_plan"]
    assert plan["actions"] == [
        {
            "rank": 1,
            "priority": "P1",
            "target": "app:1.0",
            "packages": ["libssl1.1", "openssl"],
            "installed_version": "1.0.0",
            "fixed_version": "1.2",
            "vulnerabilities": ["CVE-2024-0001", "CVE-2024-0002"],
            "by_priority": {"P1": 1, "P2": 1, "P3": 0, "P4": 0},
            "in_kev": 1,
        }
    ]
    assert plan["total_actions"] == 1
    assert plan["unfixable"] == {"count": 1, "by_status": {"not yet fixed": 1}}


def test_markdown_fix_plan() -> None:
    text = _render(MarkdownReporter(fixes=True), FIX_REPORT)
    assert text.startswith("## vulnrank fix plan: app:1.0")
    assert "1 upgrade covers 4 findings; 1 finding has no fix (1 not yet fixed)" in text
    assert "| 1 | **P1** | libssl1.1, openssl | 1.0.0 → 1.2 | 2 (P1: 1, P2: 1) | 1 |" in text
    assert (
        "| **P4** | [CVE-2024-0003](https://nvd.nist.gov/vuln/detail/CVE-2024-0003) "
        "| zlib 1.0.0 | not yet fixed |" in text
    )
    assert "[CVE-2024-0001](https://nvd.nist.gov/vuln/detail/CVE-2024-0001)" in text


def test_table_fix_plan() -> None:
    text = _render(TableReporter(width=200, fixes=True), FIX_REPORT)
    assert "vulnrank fix plan: app:1.0" in text
    assert "libssl1.1, openssl" in text
    assert "1.0.0 → 1.2" in text
    assert "2 (P1: 1, P2: 1)" in text
    assert "1 upgrade covers 4 findings; 1 finding has no fix (1 not yet fixed)" in text
    assert "Without a fix" in text
    assert "CVE-2024-0003" in text


def test_fix_plan_limit_applies_to_upgrades() -> None:
    two = Report(
        findings=tuple(
            rank(
                [
                    _scored(cve="CVE-2024-0001", fixed="1"),
                    _scored(cve="CVE-2024-0002", component="z", fixed="2"),
                ]
            )
        ),
        scanned=2,
        duplicates_removed=0,
    )
    for reporter in (MarkdownReporter(fixes=True), TableReporter(width=200, fixes=True)):
        assert "Showing the top 1 of 2 upgrades" in _render(reporter, two, limit=1)


def test_long_vulnerability_lists_are_shortened_in_the_table() -> None:
    many = Report(
        findings=tuple(rank([_scored(cve=f"CVE-2024-{n:04d}", fixed="2") for n in range(1, 8)])),
        scanned=7,
        duplicates_removed=0,
    )
    text = _render(TableReporter(width=200, fixes=True), many)
    assert "CVE-2024-0001, CVE-2024-0002, CVE-2024-0003 +4 more" in text


FIX_REPORT_WITH_ISSUES = FIX_REPORT.model_copy(
    update={"enrichment_issues": ("offline: no cached KEV catalog",)}
)


@pytest.mark.parametrize(
    "reporter",
    [MarkdownReporter(fixes=True), TableReporter(width=200, fixes=True)],
    ids=["markdown", "table"],
)
def test_fix_plan_warns_about_incomplete_enrichment(reporter: Reporter) -> None:
    text = _render(reporter, FIX_REPORT_WITH_ISSUES)
    assert "Warning: enrichment incomplete: offline: no cached KEV catalog" in text


@pytest.mark.parametrize(
    "reporter",
    [MarkdownReporter(fixes=True), TableReporter(width=200, fixes=True)],
    ids=["markdown", "table"],
)
def test_fix_plan_without_any_fix(reporter: Reporter) -> None:
    nothing_fixable = Report(
        findings=(_scored(cve="CVE-2024-0003"),), scanned=1, duplicates_removed=0
    )
    text = _render(reporter, nothing_fixable)
    assert "0 upgrades cover 0 findings; 1 finding has no fix (1 not yet fixed)" in text
    assert "Upgrade" not in text.replace("upgrades cover", "")


def test_fix_plan_table_shows_targets_when_there_are_several() -> None:
    report = Report(
        findings=(
            _scored(cve="CVE-2024-0001", fixed="2", target="api:2"),
            _scored(cve="CVE-2024-0001", fixed="2", target="web:1"),
        ),
        scanned=2,
        duplicates_removed=0,
    )
    text = _render(TableReporter(width=200, fixes=True), report)
    assert "Target" in text
    assert "api:2" in text


def test_json_fix_plan_respects_the_limit() -> None:
    two = Report(
        findings=tuple(
            rank(
                [
                    _scored(cve="CVE-2024-0001", fixed="1"),
                    _scored(cve="CVE-2024-0002", component="z", fixed="2"),
                ]
            )
        ),
        scanned=2,
        duplicates_removed=0,
    )
    plan = json.loads(_render(JsonReporter(), two, limit=1))["fix_plan"]
    assert len(plan["actions"]) == 1
    assert plan["total_actions"] == 2


def test_markdown_fix_plan_shows_targets_when_there_are_several() -> None:
    report = Report(
        findings=(
            _scored(cve="CVE-2024-0001", fixed="2", target="api:2"),
            _scored(cve="CVE-2024-0001", fixed="2", target="web:1"),
        ),
        scanned=2,
        duplicates_removed=0,
    )
    text = _render(MarkdownReporter(fixes=True), report)
    assert "| # | Tier | Target | Upgrade |" in text
    assert "| api:2 |" in text


def test_narrow_fix_table_drops_secondary_columns() -> None:
    text = _render(TableReporter(width=80, fixes=True), FIX_REPORT)
    assert "Upgrade" in text
    assert "1.0.0 → 1.2" in text
    assert "IDs" not in text
    assert "…" not in text


@pytest.mark.parametrize(
    "reporter",
    [MarkdownReporter(fixes=True), TableReporter(width=200, fixes=True)],
    ids=["markdown", "table"],
)
def test_only_the_most_urgent_unfixable_findings_are_listed(reporter: Reporter) -> None:
    many = Report(
        findings=tuple(rank([_scored(cve=f"CVE-2024-{n:04d}") for n in range(1, 9)])),
        scanned=8,
        duplicates_removed=0,
    )
    text = _render(reporter, many)
    assert "CVE-2024-0005" in text
    assert "CVE-2024-0006" not in text
    assert "3 more without a fix; see `--view findings`" in text


# --- Suppressed findings -----------------------------------------------------------------------

SUPPRESSED_REPORT = REPORT.model_copy(
    update={
        "suppressed": (
            Suppressed(
                scored=_scored(cve="CVE-2024-0009", kev=True),
                reason="accepted risk",
                source="assets.toml",
            ),
        )
    }
)


def test_summary_counts_suppressed_findings() -> None:
    assert "1 suppressed" in _render(MarkdownReporter(), SUPPRESSED_REPORT)


def test_json_lists_suppressed_findings_with_their_reason() -> None:
    document = json.loads(_render(JsonReporter(), SUPPRESSED_REPORT))
    assert document["summary"]["suppressed"] == 1
    assert document["suppressed"] == [
        {
            "id": "CVE-2024-0009",
            "target": "app:1.0",
            "component": "openssl",
            "version": "1.0.0",
            "priority": "P1",
            "in_kev": True,
            "reason": "accepted risk",
            "source": "assets.toml",
        }
    ]
