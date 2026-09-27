import pytest

from tests.builders import make_scored
from vulnrank.domain.models import Priority, ScoredFinding
from vulnrank.domain.remediation import plan_fixes, version_key

P1, P2, P3, P4 = Priority.P1, Priority.P2, Priority.P3, Priority.P4


def _finding(
    vuln_id: str,
    component: str,
    fixed: str | None,
    priority: Priority = P3,
    *,
    version: str = "1.0",
    target: str = "app:1.0",
    in_kev: bool = False,
    epss: float | None = None,
) -> ScoredFinding:
    return make_scored(
        priority=priority,
        vuln_id=vuln_id,
        component=component,
        version=version,
        fixed_version=fixed,
        target=target,
        in_kev=in_kev,
        epss=epss,
    )


# --- Version ordering -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("7.88.1-10+deb12u9", "7.88.1-10+deb12u10"),  # numeric, not alphabetical
        ("1.1.1d-0+deb10u7", "1.1.1n-0+deb10u3"),
        ("3.0.11-1~deb12u1", "3.0.12-1"),
        ("2.0", "10.0"),
        ("1.2.3", "1.2.3.1"),
        ("1.26.0", "1.26.18"),
    ],
)
def test_versions_compare_in_natural_order(lower: str, higher: str) -> None:
    assert version_key(lower) < version_key(higher)


# --- Grouping ------------------------------------------------------------------------------------


def test_one_action_per_package_targets_the_highest_fix_version() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "curl", "7.88.1-10+deb12u9"),
            _finding("CVE-2024-0002", "curl", "7.88.1-10+deb12u10"),
        ]
    )
    [action] = plan.actions
    assert action.packages == ("curl",)
    assert action.installed_version == "1.0"
    assert action.fixed_version == "7.88.1-10+deb12u10"
    assert action.vuln_ids == ("CVE-2024-0001", "CVE-2024-0002")


def test_split_packages_with_the_same_fixes_become_one_action() -> None:
    """Debian ships openssl and libssl1.1 from one source: one upgrade, counted once."""
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "openssl", "1.1.1n"),
            _finding("CVE-2024-0001", "libssl1.1", "1.1.1n"),
        ]
    )
    [action] = plan.actions
    assert action.packages == ("libssl1.1", "openssl")
    assert action.vuln_ids == ("CVE-2024-0001",)
    assert len(action.findings) == 2


def test_packages_with_different_fixes_stay_separate() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "openssl", "3.0.12"),
            _finding("CVE-2024-0002", "openssl", "3.0.12"),
            _finding("CVE-2024-0002", "libssl3", "3.0.12"),
        ]
    )
    assert sorted(a.packages for a in plan.actions) == [("libssl3",), ("openssl",)]


@pytest.mark.parametrize(
    ("other_version", "other_target"),
    [("2.0", "app:1.0"), ("1.0", "other:1.0")],
    ids=["different-installed-version", "different-target"],
)
def test_same_package_in_another_version_or_target_is_another_action(
    other_version: str, other_target: str
) -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "zlib", "2.1"),
            _finding("CVE-2024-0001", "zlib", "2.1", version=other_version, target=other_target),
        ]
    )
    assert len(plan.actions) == 2


def test_findings_without_a_fix_are_listed_separately() -> None:
    no_fix = _finding("CVE-2024-0003", "requests", None, P2)
    plan = plan_fixes([_finding("CVE-2024-0001", "zlib", "2.1"), no_fix])
    assert plan.unfixable == (no_fix,)
    assert plan.fixable_findings == 1


# --- Tiers and ordering ------------------------------------------------------------------------


def test_an_action_takes_the_most_urgent_tier_and_counts_vulnerabilities_per_tier() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "curl", "8.0", P3),
            _finding("CVE-2024-0002", "curl", "8.1", P1, in_kev=True),
            _finding("CVE-2024-0003", "curl", "8.1", P3),
        ]
    )
    [action] = plan.actions
    assert action.priority is P1
    assert action.counts == {P1: 1, P2: 0, P3: 2, P4: 0}
    assert action.kev_count == 1


def test_actions_are_ordered_by_tier_then_kev_then_size() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "small-p2", "2", P2),
            _finding("CVE-2024-0002", "big-p2", "2", P2),
            _finding("CVE-2024-0003", "big-p2", "2", P2),
            _finding("CVE-2024-0004", "kev-p2", "2", P2, in_kev=True),
            _finding("CVE-2024-0005", "only-p3", "2", P3),
            _finding("CVE-2024-0006", "p1", "2", P1),
        ]
    )
    assert [a.packages[0] for a in plan.actions] == [
        "p1",
        "kev-p2",
        "big-p2",
        "small-p2",
        "only-p3",
    ]


def test_empty_input_gives_an_empty_plan() -> None:
    plan = plan_fixes([])
    assert (plan.actions, plan.unfixable, plan.fixable_findings) == ((), (), 0)
