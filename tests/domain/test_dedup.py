from tests.builders import make_finding
from vulnrank.domain.dedup import deduplicate


def test_same_cve_component_and_target_appears_once_keeping_the_first() -> None:
    first = make_finding(cvss=9.8)
    duplicate = make_finding(cvss=7.0)
    assert deduplicate([first, duplicate]) == [first]


def test_cve_id_case_does_not_create_duplicates() -> None:
    assert len(deduplicate([make_finding(cve_id="cve-2024-0001"), make_finding()])) == 1


def test_different_target_version_component_or_cve_are_kept() -> None:
    base = make_finding()
    others = [
        make_finding(target="other:1.0"),
        make_finding(version="1.0.1"),
        make_finding(component="zlib"),
        make_finding(cve_id="CVE-2024-9999"),
    ]
    assert deduplicate([base, *others]) == [base, *others]


def test_input_order_is_preserved() -> None:
    a = make_finding(cve_id="CVE-2024-0002")
    b = make_finding(cve_id="CVE-2024-0001")
    assert deduplicate([a, b, a]) == [a, b]


def test_empty_input() -> None:
    assert deduplicate([]) == []
