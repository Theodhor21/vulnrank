"""Version ordering, checked with version strings taken from real Trivy scans."""

import pytest

from vulnrank.domain.versions import compare_versions, fix_target


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
