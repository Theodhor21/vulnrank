import logging
from pathlib import Path

import pytest

from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource, parse_cyclonedx
from vulnrank.domain.models import Finding, Severity
from vulnrank.ports.sources import FindingSource, SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "cyclonedx"


def _load(name: str) -> list[Finding]:
    source: FindingSource = CycloneDxSource(FIXTURES / name)
    return source.load()


def _bom(vulnerability: dict[str, object], **component: object) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "components": [{"bom-ref": "ref", "name": "pkg", "version": "1.0", **component}],
        "vulnerabilities": [{"id": "CVE-2024-0001", "affects": [{"ref": "ref"}], **vulnerability}],
    }


def test_one_finding_per_affected_component_including_nested_ones() -> None:
    keys = [(f.component.name, f.vulnerability.cve_id) for f in _load("basic.json")]
    assert keys == [
        ("openssl", "CVE-2023-0001"),
        ("libssl3", "CVE-2023-0002"),
        ("openssl", "CVE-2023-0002"),
        ("requests", "CVE-2023-0003"),
    ]


def test_target_comes_from_the_metadata_component() -> None:
    assert {f.target for f in _load("basic.json")} == {"demo-app:1.0"}


def test_fixed_version_is_matched_per_package_from_the_recommendation() -> None:
    fixed = {
        (f.component.name, f.vulnerability.cve_id): f.vulnerability.fixed_version
        for f in _load("basic.json")
    }
    assert fixed["libssl3", "CVE-2023-0002"] == "3.0.12-1"
    assert fixed["openssl", "CVE-2023-0001"] == "3.0.11-1~deb12u1"
    assert fixed["requests", "CVE-2023-0003"] is None


def test_fixed_version_falls_back_to_an_unaffected_version() -> None:
    affects = [{"ref": "ref", "versions": [{"version": "1.1", "status": "unaffected"}]}]
    [finding] = parse_cyclonedx(_bom({"affects": affects}), default_target="x")
    assert finding.vulnerability.fixed_version == "1.1"


def test_installed_version_falls_back_to_the_affected_version() -> None:
    affects = [{"ref": "ref", "versions": [{"version": "0.9", "status": "affected"}]}]
    [finding] = parse_cyclonedx(_bom({"affects": affects}, version=""), default_target="x")
    assert finding.component.version == "0.9"


def test_installed_version_is_empty_when_nothing_states_it() -> None:
    affects = [{"ref": "ref", "versions": [{"version": "1.1", "status": "unaffected"}]}]
    [finding] = parse_cyclonedx(_bom({"affects": affects}, version=""), default_target="x")
    assert finding.component.version == ""


@pytest.mark.parametrize(
    ("ratings", "source", "expected"),
    [
        pytest.param(
            [
                {"source": {"name": "nvd"}, "severity": "low"},
                {"source": {"name": "debian"}, "severity": "high"},
            ],
            {"name": "debian"},
            Severity.HIGH,
            id="own-source-first",
        ),
        pytest.param(
            [
                {"source": {"name": "redhat"}, "severity": "low"},
                {"source": {"name": "nvd"}, "severity": "critical"},
            ],
            None,
            Severity.CRITICAL,
            id="then-nvd",
        ),
        pytest.param(
            [{"source": {"name": "redhat"}, "severity": "info"}],
            None,
            Severity.LOW,
            id="then-first-info-maps-to-low",
        ),
        pytest.param(
            [{"score": 5.0, "method": "CVSSv31"}], None, Severity.UNKNOWN, id="no-severity"
        ),
    ],
)
def test_severity_selection(
    ratings: list[object], source: dict[str, str] | None, expected: Severity
) -> None:
    [finding] = parse_cyclonedx(_bom({"ratings": ratings, "source": source}), default_target="x")
    assert finding.vulnerability.severity is expected


def test_cvss_v2_and_unknown_methods_are_ignored() -> None:
    ratings = [{"score": 10.0, "method": "CVSSv2"}, {"score": 4.0, "method": "OWASP"}]
    [finding] = parse_cyclonedx(_bom({"ratings": ratings}), default_target="x")
    assert finding.vulnerability.cvss_score is None


def test_malformed_records_are_logged_and_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        findings = _load("malformed.json")
    assert [(f.component.name, f.vulnerability.cve_id) for f in findings] == [
        ("zlib", "CVE-2023-1000")
    ]
    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 6
    assert "components[1]" in warnings[0]
    assert "name" in warnings[0]
    assert "components[2]" in warnings[1]
    assert "no affected components" in warnings[2]
    assert "unknown component reference 'pkg:apk/alpine/missing@9.9'" in warnings[3]
    assert "cvss_score" in warnings[4]
    assert "vulnerabilities[4]" in warnings[5]


def test_sbom_without_vulnerabilities_explains_how_to_get_them(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        findings = parse_cyclonedx({"bomFormat": "CycloneDX", "components": []}, default_target="x")
    assert findings == []
    assert "--scanners vuln" in caplog.text


def test_file_name_is_the_target_without_metadata() -> None:
    [finding] = parse_cyclonedx(_bom({}), default_target="sbom.json")
    assert finding.target == "sbom.json"


@pytest.mark.parametrize(
    "document",
    [{"SchemaVersion": 2, "Results": []}, {"bomFormat": "SPDX"}, "just a string"],
    ids=["trivy", "other-format", "string"],
)
def test_wrong_format_is_a_source_error(document: object) -> None:
    with pytest.raises(SourceError, match="not a CycloneDX JSON document"):
        parse_cyclonedx(document, default_target="x")
