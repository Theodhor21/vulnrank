import pytest
from pydantic import ValidationError

from tests.builders import make_finding
from vulnrank.domain.models import (
    Component,
    Criticality,
    Enrichment,
    Priority,
    Reason,
    Vulnerability,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("cve-2021-44228", "CVE-2021-44228"),
        ("  CVE-2014-0160 ", "CVE-2014-0160"),
        ("CVE-2023-1234567", "CVE-2023-1234567"),
    ],
)
def test_cve_id_is_validated_and_normalised(raw: str, expected: str) -> None:
    assert Vulnerability(cve_id=raw).cve_id == expected


@pytest.mark.parametrize(
    "raw",
    ["", "CVE-2021-123", "CVE-21-44228", "CVE-2021-ABCD", "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228x"],
)
def test_invalid_cve_id_is_rejected(raw: str) -> None:
    with pytest.raises(ValidationError, match="not a valid CVE ID"):
        Vulnerability(cve_id=raw)


@pytest.mark.parametrize("cvss", [-0.1, 10.1])
def test_cvss_must_be_between_0_and_10(cvss: float) -> None:
    with pytest.raises(ValidationError):
        Vulnerability(cve_id="CVE-2024-0001", cvss_score=cvss)


@pytest.mark.parametrize("epss", [-0.01, 1.01])
def test_epss_must_be_a_probability(epss: float) -> None:
    with pytest.raises(ValidationError):
        Enrichment(epss_score=epss)


def test_component_name_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        Component(name="", version="1.0")


def test_models_are_immutable() -> None:
    vulnerability = Vulnerability(cve_id="CVE-2024-0001")
    with pytest.raises(ValidationError):
        vulnerability.cvss_score = 9.8  # pyright: ignore[reportAttributeAccessIssue]


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Reason.model_validate({"text": "x", "colour": "red"})


@pytest.mark.parametrize(
    ("fixed_version", "expected"), [("1.2.9", True), (None, False), ("", False)]
)
def test_fix_available(fixed_version: str | None, expected: bool) -> None:
    vulnerability = Vulnerability(cve_id="CVE-2024-0001", fixed_version=fixed_version)
    assert vulnerability.fix_available is expected


def test_finding_key_identifies_cve_in_component_and_target() -> None:
    finding = make_finding(cve_id="cve-2024-0001", component="zlib", version="1.2", target="img")
    assert finding.key == ("img", "zlib", "1.2", "CVE-2024-0001")


def test_priority_rank_and_comparison() -> None:
    assert [p.rank for p in Priority] == [1, 2, 3, 4]
    assert Priority.P1.is_at_least(Priority.P2)
    assert Priority.P2.is_at_least(Priority.P2)
    assert not Priority.P3.is_at_least(Priority.P2)


def test_criticality_ordering() -> None:
    assert Criticality.CRITICAL.is_at_least(Criticality.HIGH)
    assert Criticality.HIGH.is_at_least(Criticality.HIGH)
    assert not Criticality.MEDIUM.is_at_least(Criticality.HIGH)
