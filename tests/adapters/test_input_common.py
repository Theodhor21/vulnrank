import pytest

from vulnrank.adapters.inputs._common import (
    CvssCandidate,
    ecosystem_from_purl,
    parse_severity,
    pick_cvss,
)
from vulnrank.domain.models import Severity


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("medium", Severity.MEDIUM),
        (" High ", Severity.HIGH),
        ("info", Severity.LOW),
        ("none", Severity.LOW),
        ("UNKNOWN", Severity.UNKNOWN),
        ("weird", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ],
)
def test_parse_severity(raw: str | None, expected: Severity) -> None:
    assert parse_severity(raw) is expected


@pytest.mark.parametrize(
    ("candidates", "expected"),
    [
        pytest.param([], None, id="none"),
        pytest.param(
            [CvssCandidate("redhat", 3, 8.1), CvssCandidate("nvd", 3, 9.8)], 9.8, id="nvd-first"
        ),
        pytest.param(
            [CvssCandidate("redhat", 3, 8.1), CvssCandidate("bitnami", 3, 7.0)],
            7.0,
            id="then-alphabetical",
        ),
        pytest.param(
            [CvssCandidate("nvd", 4, 9.3), CvssCandidate("ghsa", 3, 5.3)], 5.3, id="v3-over-v4"
        ),
        pytest.param([CvssCandidate("nvd", 4, 9.3)], 9.3, id="v4-when-only-option"),
    ],
)
def test_pick_cvss(candidates: list[CvssCandidate], expected: float | None) -> None:
    assert pick_cvss(candidates) == expected


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:deb/debian/openssl@3.0.9-1?arch=amd64", "deb"),
        ("pkg:pypi/requests@2.25.0", "pypi"),
        ("pkg:npm/%40angular/core@16.0.0", "npm"),
        ("pkg:/weird", None),
        ("not-a-purl", None),
        (None, None),
    ],
)
def test_ecosystem_from_purl(purl: str | None, expected: str | None) -> None:
    assert ecosystem_from_purl(purl) == expected
