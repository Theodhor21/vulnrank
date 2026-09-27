from collections.abc import Collection, Mapping

from tests.builders import make_asset, make_finding
from vulnrank.application.service import prioritise
from vulnrank.domain.models import (
    Asset,
    Criticality,
    EpssScore,
    Finding,
    KevEntry,
    Priority,
)
from vulnrank.domain.policy import ScoringPolicy


class ListSource:
    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def load(self) -> list[Finding]:
        return self.findings


class NoEpss:
    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        return {}


class FixedEpss:
    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = scores

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        return {c: EpssScore(score=s, percentile=0.5) for c, s in self._scores.items()}


class NoKev:
    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        return {}


def _assets(target: str) -> Asset:
    critical = make_asset(target="prod", criticality=Criticality.CRITICAL, internet_exposed=True)
    return critical if target == "prod" else make_asset(target=target)


def test_findings_are_deduplicated_enriched_scored_and_ranked() -> None:
    source = ListSource(
        [
            make_finding(cve_id="CVE-2024-0001", cvss=7.5),
            make_finding(cve_id="CVE-2024-0002", target="prod"),
            make_finding(cve_id="CVE-2024-0001", cvss=7.5),
        ]
    )
    report = prioritise(
        source,
        FixedEpss({"CVE-2024-0002": 0.2}),
        NoKev(),
        asset_for=_assets,
        policy=ScoringPolicy(),
    )
    assert [(f.finding.vulnerability.cve_id, f.priority) for f in report.findings] == [
        ("CVE-2024-0002", Priority.P1),  # EPSS 20% on an exposed critical asset
        ("CVE-2024-0001", Priority.P3),
    ]
    assert (report.scanned, report.duplicates_removed) == (3, 1)
    assert report.findings[0].asset.target == "prod"


def test_empty_scan_gives_an_empty_report() -> None:
    report = prioritise(
        ListSource([]), NoEpss(), NoKev(), asset_for=_assets, policy=ScoringPolicy()
    )
    assert report.findings == ()
    assert report.scanned == 0
