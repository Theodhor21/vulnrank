"""Version ordering, checked with version strings taken from real Trivy scans."""

import pytest

from vulnrank.domain.versions import compare_versions, fix_target, upgrade_target


@pytest.mark.parametrize(
    ("lower", "higher", "ecosystem"),
    [
        # Debian (dpkg rules): epochs dominate, `~` sorts before everything, even the end.
        pytest.param("2.0-1", "1:1.2-1", "deb", id="deb-epoch-wins"),
        pytest.param("1.2.3~rc1", "1.2.3", "deb", id="deb-tilde-is-pre-release"),
        pytest.param("3.0.11-1~deb12u1", "3.0.11-1", "deb", id="deb-backport-before-release"),
        pytest.param("7.88.1-10+deb12u9", "7.88.1-10+deb12u10", "deb", id="deb-numeric"),
        pytest.param("1.1.1d-0+deb10u7", "1.1.1n-0+deb10u3", "deb", id="deb-letters"),
        pytest.param("0.6.1-2", "0.6.1-2+deb10u3", "deb", id="deb-security-update"),
        pytest.param("1:2.39.5-0+deb12u1", "1:2.39.5-0+deb12u3", "deb", id="deb-same-epoch"),
        # npm / SemVer: a pre-release comes before its release.
        pytest.param("1.0.0-beta.1", "1.0.0", "npm", id="npm-pre-release"),
        pytest.param("1.0.0-alpha", "1.0.0-beta", "npm", id="npm-alpha-before-beta"),
        pytest.param("1.0.0-rc.1", "1.0.0", "npm", id="npm-rc"),
        pytest.param("9.0.7", "10.2.3", "npm", id="npm-numeric-major"),
        pytest.param("1.2.3", "1.2.3.1", "npm", id="longer-is-newer"),
        pytest.param("1.0.beta", "1.0.1", "npm", id="number-outranks-word"),
        # PyPI (PEP 440 basics).
        pytest.param("1.0a1", "1.0", "pypi", id="pypi-alpha"),
        pytest.param("1.0rc1", "1.0", "pypi", id="pypi-rc"),
        pytest.param("1.0", "1.0.post1", "pypi", id="pypi-post-release"),
        # Alpine: `-r1` is a package revision, not a pre-release.
        pytest.param("1.2.3-r0", "1.2.3-r1", "apk", id="apk-revision"),
        pytest.param("1.2.3", "1.2.3-r1", "apk", id="apk-revision-after-release"),
        # Maven snapshots come before the release.
        pytest.param("1.0-SNAPSHOT", "1.0", "maven", id="maven-snapshot"),
        # Unknown ecosystem: the generic rules apply.
        pytest.param("2.0", "10.0", None, id="unknown-numeric"),
    ],
)
def test_version_order(lower: str, higher: str, ecosystem: str | None) -> None:
    assert compare_versions(lower, higher, ecosystem) < 0
    assert compare_versions(higher, lower, ecosystem) > 0


@pytest.mark.parametrize("ecosystem", ["deb", "npm", None])
def test_equal_versions(ecosystem: str | None) -> None:
    assert compare_versions("1.2.3", "1.2.3", ecosystem) == 0


@pytest.mark.parametrize(
    ("installed", "fixed", "ecosystem", "expected"),
    [
        # Trivy lists one fix per release branch; the smallest upgrade is the lowest fix above
        # the installed version. Strings from the Juice Shop scan in examples/.
        ("3.0.5", "10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.4", "npm", "3.1.4"),
        ("3.1.2", "2.5.1, 4.6.2", "npm", "4.6.2"),
        ("7.4.6", "5.2.5, 6.2.4, 7.5.11, 8.21.0", "npm", "7.5.11"),
        ("3.1.0", "3.0.8, 3.1.2", "npm", "3.1.2"),
        ("1.0", "1.2", "npm", "1.2"),
        ("1.0", " 1.2 ,, ", "npm", "1.2"),
        # No listed fix is above the installed version: fall back to the highest one.
        ("5.0", "1.0, 2.0", "npm", "2.0"),
    ],
)
def test_fix_target_picks_the_smallest_upgrade(
    installed: str, fixed: str, ecosystem: str, expected: str
) -> None:
    assert fix_target(installed, fixed, ecosystem) == expected


# --- The upgrade that fixes every listed CVE --------------------------------------------------

GRPC_FIXES = [  # etcd v3.5.9, google.golang.org/grpc v1.41.0 (real Trivy output)
    "1.79.3",
    "1.83.1",
    "1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3, "
    "1.85.0-dev.0.20260825072537-93e31b48545e",
    "1.82.1",
    "1.56.3, 1.57.1, 1.58.3",
    "1.83.1",
]


@pytest.mark.parametrize(
    ("installed", "fix_lists", "ecosystem", "expected"),
    [
        # 1.83.1 is the highest single pick, but CVE-2026-84445 is fixed on 1.83.x only in 1.83.2.
        pytest.param("v1.41.0", GRPC_FIXES, "golang", "1.83.2", id="grpc-every-cve-fixed"),
        pytest.param(
            "v1.19.9",
            [
                "1.25.13, 1.26.6, 1.27.0-rc.3",
                "1.24.13, 1.25.7, 1.26.0-rc.3",
                "1.21.11, 1.22.4",
                "1.19.10, 1.20.5",
            ],
            "golang",
            "1.25.13",
            id="go-stdlib-branches",
        ),
        # A `v` prefix must not make the installed version older than every fix (a downgrade).
        pytest.param("v1.21.0", ["1.21.5, 1.20.12"], "golang", "1.21.5", id="go-v-prefix"),
        # Only a pre-release fixes it: better than nothing, so it is still offered.
        pytest.param("1.0.0", ["1.1.0-rc.1"], "npm", "1.1.0-rc.1", id="pre-release-only"),
        # Version ranges leak into FixedVersion: `>=4.17.19` means 4.17.19.
        pytest.param("4.17.15", [">=4.17.19", "4.17.21"], "npm", "4.17.21", id="range-operator"),
        # Trivy drops the Debian epoch from fixed versions; the installed epoch still applies.
        pytest.param(
            "1:2.33.1-0.1",
            ["2.33.1-0.1+deb10u1"],
            "deb",
            "1:2.33.1-0.1+deb10u1",
            id="deb-epoch-inherited",
        ),
    ],
)
def test_upgrade_target_fixes_every_cve(
    installed: str, fix_lists: list[str], ecosystem: str, expected: str
) -> None:
    assert upgrade_target(installed, fix_lists, ecosystem) == expected


@pytest.mark.parametrize(("a", "b"), [("v1.2.0", "1.2.0"), ("V2", "2")])
def test_a_leading_v_is_ignored(a: str, b: str) -> None:
    assert compare_versions(a, b, "golang") == 0


def test_no_listed_fix_gives_no_target() -> None:
    assert upgrade_target("1.0", ["", " , "], "npm") == ""


def test_debian_takes_the_lowest_listed_fix_above_the_installed_version() -> None:
    assert upgrade_target("1.0-1", ["1.2-1, 1.1-1"], "deb") == "1.1-1"
