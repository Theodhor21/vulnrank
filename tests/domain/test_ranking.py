from tests.builders import make_scored
from vulnrank.domain.models import Priority
from vulnrank.domain.scoring import rank


def test_tier_comes_first() -> None:
    p3 = make_scored(priority=Priority.P3, epss=0.9, cve_id="CVE-2024-0003")
    p1 = make_scored(priority=Priority.P1, epss=0.01, cve_id="CVE-2024-0001")
    p2 = make_scored(priority=Priority.P2, cve_id="CVE-2024-0002")
    assert rank([p3, p1, p2]) == [p1, p2, p3]


def test_higher_epss_first_within_a_tier_and_unknown_epss_last() -> None:
    low = make_scored(priority=Priority.P2, epss=0.2, cve_id="CVE-2024-0001")
    high = make_scored(priority=Priority.P2, epss=0.8, cve_id="CVE-2024-0002")
    unknown = make_scored(priority=Priority.P2, cve_id="CVE-2024-0003")
    zero = make_scored(priority=Priority.P2, epss=0.0, cve_id="CVE-2024-0004")
    assert rank([unknown, low, zero, high]) == [high, low, zero, unknown]


def test_cvss_breaks_epss_ties_and_unknown_cvss_last() -> None:
    low = make_scored(priority=Priority.P3, epss=0.1, cvss=7.1, cve_id="CVE-2024-0001")
    high = make_scored(priority=Priority.P3, epss=0.1, cvss=8.8, cve_id="CVE-2024-0002")
    unknown = make_scored(priority=Priority.P3, epss=0.1, cve_id="CVE-2024-0003")
    assert rank([unknown, low, high]) == [high, low, unknown]


def test_fixable_first_when_everything_else_ties() -> None:
    unfixable = make_scored(priority=Priority.P3, cvss=7.5, cve_id="CVE-2024-0001")
    fixable = make_scored(
        priority=Priority.P3, cvss=7.5, fixed_version="2.0", cve_id="CVE-2024-0002"
    )
    assert rank([unfixable, fixable]) == [fixable, unfixable]


def test_full_ties_are_ordered_deterministically() -> None:
    a = make_scored(priority=Priority.P4, cve_id="CVE-2024-0001")
    b = make_scored(priority=Priority.P4, cve_id="CVE-2024-0002")
    assert rank([b, a]) == rank([a, b]) == [a, b]


def test_rank_does_not_mutate_its_input() -> None:
    items = [make_scored(priority=Priority.P4), make_scored(priority=Priority.P1)]
    snapshot = list(items)
    rank(items)
    assert items == snapshot


def test_rank_of_nothing_is_empty() -> None:
    assert rank([]) == []
