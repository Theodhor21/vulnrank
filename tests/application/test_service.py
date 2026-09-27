import logging
from collections.abc import Collection, Mapping
from datetime import date

import pytest

from tests.builders import make_asset, make_finding
from vulnrank.application.service import prioritise
from vulnrank.domain.models import (
    Asset,
    Criticality,
    EpssScore,
    Finding,
    KevEntry,
    Priority,
    ScanResult,
)
from vulnrank.domain.baseline import Baseline, ChangeState
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.suppression import IgnoreRule, VexStatement, VexStatus


class ListSource:
    def __init__(self, findings: list[Finding], skipped: int = 0) -> None:
        self.findings = findings
        self.skipped = skipped

    def load(self) -> ScanResult:
        return ScanResult(findings=tuple(self.findings), skipped=self.skipped)


class NoEpss:
    def __init__(self, issues: tuple[str, ...] = ()) -> None:
        self._issues = issues

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        return {}

    def issues(self) -> tuple[str, ...]:
        return self._issues


class FixedEpss:
    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = scores

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        return {c: EpssScore(score=s, percentile=0.5) for c, s in self._scores.items()}

    def issues(self) -> tuple[str, ...]:
        return ()


class NoKev:
    def __init__(self, issues: tuple[str, ...] = ()) -> None:
        self._issues = issues

    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        return {}

    def issues(self) -> tuple[str, ...]:
        return self._issues


class KevWith:
    def __init__(self, cve: str) -> None:
        self._cve = cve

    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        return {self._cve: KevEntry(cve_id=self._cve, date_added=date(2024, 1, 1))}

    def issues(self) -> tuple[str, ...]:
        return ()


def _assets(target: str) -> Asset:
    critical = make_asset(target="prod", criticality=Criticality.CRITICAL, internet_exposed=True)
    return critical if target == "prod" else make_asset(target=target)


def test_findings_are_deduplicated_enriched_scored_and_ranked() -> None:
    source = ListSource(
        [
            make_finding(vuln_id="CVE-2024-0001", cvss=7.5),
            make_finding(vuln_id="CVE-2024-0002", target="prod"),
            make_finding(vuln_id="CVE-2024-0001", cvss=7.5),
        ]
    )
    report = prioritise(
        source,
        FixedEpss({"CVE-2024-0002": 0.2}),
        NoKev(),
        asset_for=_assets,
        policy=ScoringPolicy(),
    )
    assert [(f.finding.vulnerability.vuln_id, f.priority) for f in report.findings] == [
        ("CVE-2024-0002", Priority.P1),  # EPSS 20% on an exposed critical asset
        ("CVE-2024-0001", Priority.P3),
    ]
    assert (report.scanned, report.duplicates_removed, report.skipped) == (3, 1, 0)
    assert report.findings[0].asset.target == "prod"


def test_empty_scan_gives_an_empty_report() -> None:
    report = prioritise(
        ListSource([]), NoEpss(), NoKev(), asset_for=_assets, policy=ScoringPolicy()
    )
    assert report.findings == ()
    assert report.scanned == 0


def test_skipped_records_count_towards_the_records_scanned() -> None:
    report = prioritise(
        ListSource([make_finding()], skipped=2),
        NoEpss(),
        NoKev(),
        asset_for=_assets,
        policy=ScoringPolicy(),
    )
    assert (report.scanned, report.skipped) == (3, 2)


def test_enrichment_problems_are_reported() -> None:
    report = prioritise(
        ListSource([make_finding()]),
        NoEpss(("EPSS lookup failed for 1 CVE(s)",)),
        NoKev(("KEV catalog unavailable",)),
        asset_for=_assets,
        policy=ScoringPolicy(),
    )
    assert report.enrichment_issues == (
        "EPSS lookup failed for 1 CVE(s)",
        "KEV catalog unavailable",
    )


def test_target_override_renames_every_finding() -> None:
    report = prioritise(
        ListSource([make_finding(target="scan.json")]),
        NoEpss(),
        NoKev(),
        asset_for=_assets,
        policy=ScoringPolicy(),
        target="prod",
    )
    assert report.findings[0].finding.target == "prod"
    assert report.findings[0].asset.criticality is Criticality.CRITICAL


def test_suppressed_findings_are_reported_apart_and_do_not_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    exploited = KevWith("CVE-2024-0002")
    rule = IgnoreRule(vuln_id="CVE-2024-0002", reason="accepted", source="assets.toml")
    expired = IgnoreRule(
        vuln_id="CVE-2024-0001", reason="old", source="assets.toml", expires=date(2026, 1, 1)
    )
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        report = prioritise(
            ListSource(
                [make_finding(vuln_id="CVE-2024-0001"), make_finding(vuln_id="CVE-2024-0002")]
            ),
            NoEpss(),
            exploited,
            asset_for=_assets,
            policy=ScoringPolicy(),
            rules=(rule, expired),
            today=date(2026, 9, 28),
        )
    assert [f.finding.vulnerability.vuln_id for f in report.findings] == ["CVE-2024-0001"]
    assert [s.scored.finding.vulnerability.vuln_id for s in report.suppressed] == ["CVE-2024-0002"]
    assert not report.has_findings_at_or_above(Priority.P1)
    assert "suppressed CVE-2024-0002 is in CISA KEV" in caplog.text
    assert "ignore rule for CVE-2024-0001 expired on 2026-01-01" in caplog.text


def test_vex_statements_are_applied() -> None:
    statement = VexStatement(vuln_ids=("CVE-2024-0001",), status=VexStatus.FIXED, source="vex.json")
    report = prioritise(
        ListSource([make_finding()]),
        NoEpss(),
        NoKev(),
        asset_for=_assets,
        policy=ScoringPolicy(),
        statements=(statement,),
    )
    assert report.findings == ()
    assert report.suppressed[0].reason == "VEX: fixed"


def test_a_baseline_marks_changes_and_counts_resolved(caplog: pytest.LogCaptureFixture) -> None:
    baseline = Baseline(
        priorities={
            ("app", "openssl", "CVE-2024-0001"): Priority.P3,
            ("app", "openssl", "CVE-2024-0009"): Priority.P1,
        },
        complete=False,
    )
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        report = prioritise(
            ListSource([make_finding(vuln_id="CVE-2024-0001", cvss=7.5)]),
            NoEpss(),
            NoKev(),
            asset_for=_assets,
            policy=ScoringPolicy(),
            baseline=baseline,
        )
    [scored] = report.findings
    assert scored.change is not None
    assert scored.change.state is ChangeState.UNCHANGED
    assert report.baseline_resolved == 1
    assert "baseline does not list every finding" in caplog.text
