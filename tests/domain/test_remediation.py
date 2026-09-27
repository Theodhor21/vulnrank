import pytest

from tests.builders import make_scored
from vulnrank.domain.models import FixStatus, Priority, ScoredFinding
from vulnrank.domain.remediation import plan_fixes

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
    ecosystem: str | None = None,
    status: FixStatus | None = None,
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
        ecosystem=ecosystem,
        status=status,
    )


# --- Grouping ------------------------------------------------------------------------------------


def test_one_action_per_package_targets_the_highest_fix_version() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "curl", "7.88.1-10+deb12u9", ecosystem="deb"),
            _finding("CVE-2024-0002", "curl", "7.88.1-10+deb12u10", ecosystem="deb"),
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


# --- Version edge cases found in real scans -------------------------------------------------------


def test_multi_branch_fixes_pick_the_smallest_upgrade_that_fixes_everything() -> None:
    """CVE-A is fixed on the 3.1 branch in 3.1.2; CVE-B in 3.1.1. Only 3.1.2 fixes both."""
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "lib", "3.0.8, 3.1.2", version="3.1.0", ecosystem="npm"),
            _finding("CVE-2024-0002", "lib", "3.1.1", version="3.1.0", ecosystem="npm"),
        ]
    )
    assert plan.actions[0].fixed_version == "3.1.2"


@pytest.mark.parametrize(
    ("fixes", "expected"),
    [
        (("1.2.3", "1.2.3~rc1"), "1.2.3"),
        (("1:1.2-1", "2.0-1"), "1:1.2-1"),
    ],
    ids=["tilde-pre-release", "epoch"],
)
def test_debian_versions_follow_dpkg_rules(fixes: tuple[str, str], expected: str) -> None:
    plan = plan_fixes(
        [
            _finding(f"CVE-2024-000{n}", "lib", fix, version="0.1", ecosystem="deb")
            for n, fix in enumerate(fixes, start=1)
        ]
    )
    assert plan.actions[0].fixed_version == expected


def test_same_name_in_different_ecosystems_is_never_merged() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "debug", "4.3.2", version="4.3.1", ecosystem="npm"),
            _finding("CVE-2024-0002", "debug", "4.3.9", version="4.3.1", ecosystem="pypi"),
        ]
    )
    assert sorted(a.fixed_version for a in plan.actions) == ["4.3.2", "4.3.9"]


def test_unfixable_findings_are_counted_by_vendor_status() -> None:
    plan = plan_fixes(
        [
            _finding("CVE-2024-0001", "a", None, status=FixStatus.WILL_NOT_FIX),
            _finding("CVE-2024-0002", "b", None, status=FixStatus.WILL_NOT_FIX),
            _finding("CVE-2024-0003", "c", None, status=FixStatus.FIX_DEFERRED),
            _finding("CVE-2024-0004", "d", None, status=FixStatus.END_OF_LIFE),
            _finding("CVE-2024-0005", "e", None, status=FixStatus.AFFECTED),
            _finding("CVE-2024-0006", "f", None),
        ]
    )
    assert plan.unfixable_by_status == {
        "not yet fixed": 2,
        "will not fix": 2,
        "deferred": 1,
        "end-of-life": 1,
    }
