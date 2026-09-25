import logging
from pathlib import Path

import pytest

from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource, parse_trivy_report
from vulnrank.domain.models import Component, Finding, Severity, Vulnerability
from vulnrank.ports.sources import FindingSource, SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "trivy"


def _load(name: str) -> list[Finding]:
    source: FindingSource = TrivyJsonSource(FIXTURES / name)
    return source.load()


def test_findings_are_normalised_into_the_domain_model() -> None:
    first = _load("basic.json")[0]
    assert first == Finding(
        component=Component(
            name="openssl",
            version="3.0.9-1",
            purl="pkg:deb/debian/openssl@3.0.9-1?arch=amd64&distro=debian-12.1",
            ecosystem="deb",
        ),
        vulnerability=Vulnerability(
            cve_id="CVE-2023-0001",
            severity=Severity.HIGH,
            cvss_score=7.5,
            fixed_version="3.0.11-1~deb12u1",
        ),
        target="demo-app:1.0",
    )


def test_every_cve_in_every_result_is_read() -> None:
    keys = [(f.component.name, f.vulnerability.cve_id) for f in _load("basic.json")]
    assert keys == [
        ("openssl", "CVE-2023-0001"),
        ("libssl3", "CVE-2023-0002"),
        ("openssl", "CVE-2023-0002"),
        ("requests", "CVE-2023-0003"),
    ]


def test_nvd_cvss_v3_is_preferred_and_v3_beats_v4() -> None:
    by_key = {(f.component.name, f.vulnerability.cve_id): f for f in _load("basic.json")}
    assert by_key["libssl3", "CVE-2023-0002"].vulnerability.cvss_score == 9.8
    assert by_key["requests", "CVE-2023-0003"].vulnerability.cvss_score == 5.3


def test_missing_fixed_version_means_no_fix() -> None:
    requests = _load("basic.json")[-1]
    assert requests.vulnerability.fixed_version is None


def test_non_cve_advisories_are_skipped_with_an_info_log(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="vulnrank"):
        findings = _load("basic.json")
    assert all(f.vulnerability.cve_id.startswith("CVE-") for f in findings)
    assert "GHSA-aaaa-bbbb-cccc" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_malformed_records_are_logged_and_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        findings = _load("malformed.json")
    assert [f.vulnerability.cve_id for f in findings] == ["CVE-2023-1000"]
    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 5
    assert "Results[0]" in warnings[0]
    assert "Vulnerabilities[1]" in warnings[1]
    assert "PkgName" in warnings[1]
    assert "not a valid CVE ID" in warnings[2]
    assert "cvss_score" in warnings[3]
    assert "Vulnerabilities[4]" in warnings[4]


def test_ecosystem_falls_back_to_the_result_type_without_a_purl() -> None:
    assert _load("malformed.json")[0].component.ecosystem == "alpine"


def test_file_name_is_the_target_when_artifact_name_is_missing() -> None:
    findings = parse_trivy_report(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "x",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "a",
                            "InstalledVersion": "1",
                        }
                    ],
                }
            ],
        },
        default_target="scan.json",
    )
    assert findings[0].target == "scan.json"


@pytest.mark.parametrize(
    "document",
    [
        {"bomFormat": "CycloneDX"},
        {"SchemaVersion": 2, "Results": "nope"},
        ["not", "an", "object"],
    ],
    ids=["cyclonedx", "results-not-a-list", "array"],
)
def test_wrong_format_is_a_source_error(document: object) -> None:
    with pytest.raises(SourceError, match="not a Trivy JSON report"):
        parse_trivy_report(document, default_target="x")


def test_invalid_json_is_a_source_error(tmp_path: Path) -> None:
    path = tmp_path / "scan.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SourceError, match="not valid JSON"):
        TrivyJsonSource(path).load()


def test_missing_file_is_a_source_error(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="cannot read"):
        TrivyJsonSource(tmp_path / "missing.json").load()
