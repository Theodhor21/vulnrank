from collections.abc import Collection, Mapping
from datetime import date

from vulnrank.application.enrichment import enrich
from vulnrank.domain.models import Enrichment, EpssScore, KevEntry


class FakeEpss:
    def __init__(self, scores: dict[str, EpssScore]) -> None:
        self.scores_by_cve = scores
        self.requested: list[str] = []

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        self.requested = list(cve_ids)
        return {cve: s for cve, s in self.scores_by_cve.items() if cve in cve_ids}

    def issues(self) -> tuple[str, ...]:
        return ()


class FakeKev:
    def __init__(self, entries: dict[str, KevEntry]) -> None:
        self.entries = entries
        self.requested: list[str] = []

    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        self.requested = list(cve_ids)
        return {cve: e for cve, e in self.entries.items() if cve in cve_ids}

    def issues(self) -> tuple[str, ...]:
        return ()


def test_each_cve_gets_one_combined_enrichment() -> None:
    epss = FakeEpss({"CVE-2023-0001": EpssScore(score=0.9, percentile=0.99)})
    kev = FakeKev({"CVE-2023-0002": KevEntry(cve_id="CVE-2023-0002", date_added=date(2024, 1, 10))})
    result = enrich(["CVE-2023-0002", "CVE-2023-0001", "CVE-2023-0003", "CVE-2023-0001"], epss, kev)
    assert result == {
        "CVE-2023-0001": Enrichment(epss_score=0.9, epss_percentile=0.99),
        "CVE-2023-0002": Enrichment(in_kev=True, kev_date_added=date(2024, 1, 10)),
        "CVE-2023-0003": Enrichment(),
    }
    assert epss.requested == ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]


def test_no_cves_means_no_enrichment() -> None:
    assert enrich([], FakeEpss({}), FakeKev({})) == {}


def test_only_cve_ids_are_looked_up_but_every_advisory_gets_an_enrichment() -> None:
    epss, kev = FakeEpss({}), FakeKev({})
    result = enrich(["GHSA-jfh8-c2jp-5v3q", "CVE-2023-0001"], epss, kev)
    assert epss.requested == ["CVE-2023-0001"]
    assert kev.requested == ["CVE-2023-0001"]
    assert result["GHSA-jfh8-c2jp-5v3q"] == Enrichment()
