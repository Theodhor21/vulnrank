import logging
from pathlib import Path

import pytest

from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource, parse_trivy_report
from vulnrank.domain.models import Component, Finding, FixStatus, Severity, Vulnerability
from vulnrank.ports.sources import FindingSource, SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "trivy"


def _load(name: str) -> list[Finding]:
    source: FindingSource = TrivyJsonSource(FIXTURES / name)
    return list(source.load().findings)


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
            vuln_id="CVE-2023-0001",
            severity=Severity.HIGH,
            cvss_score=7.5,
            fixed_version="3.0.11-1~deb12u1",
            status=FixStatus.FIXED,
        ),
        target="demo-app:1.0",
    )


def test_every_cve_in_every_result_is_read() -> None:
    keys = [(f.component.name, f.vulnerability.vuln_id) for f in _load("basic.json")]
    assert keys == [
        ("openssl", "CVE-2023-0001"),
        ("libssl3", "CVE-2023-0002"),
        ("openssl", "CVE-2023-0002"),
        ("requests", "CVE-2023-0003"),
        ("urllib3", "GHSA-aaaa-bbbb-cccc"),
    ]


def test_nvd_cvss_v3_is_preferred_and_v3_beats_v4() -> None:
    by_key = {(f.component.name, f.vulnerability.vuln_id): f for f in _load("basic.json")}
    assert by_key["libssl3", "CVE-2023-0002"].vulnerability.cvss_score == 9.8
    assert by_key["requests", "CVE-2023-0003"].vulnerability.cvss_score == 5.3


def test_missing_fixed_version_means_no_fix() -> None:
    requests = _load("basic.json")[3]
    assert requests.vulnerability.fixed_version is None
    assert requests.vulnerability.status is FixStatus.AFFECTED


def test_advisories_without_a_cve_are_kept() -> None:
    ghsa = _load("basic.json")[-1]
    assert ghsa.vulnerability.vuln_id == "GHSA-aaaa-bbbb-cccc"
    assert ghsa.vulnerability.severity is Severity.LOW
    assert ghsa.vulnerability.fixed_version == "1.26.18"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("fixed", FixStatus.FIXED),
        ("affected", FixStatus.AFFECTED),
        ("will_not_fix", FixStatus.WILL_NOT_FIX),
        ("fix_deferred", FixStatus.FIX_DEFERRED),
        ("end_of_life", FixStatus.END_OF_LIFE),
        ("not_affected", FixStatus.NOT_AFFECTED),
        ("under_investigation", FixStatus.UNDER_INVESTIGATION),
        ("something_new", None),
        (None, None),
    ],
)
def test_vendor_fix_status_is_read(raw: str | None, expected: FixStatus | None) -> None:
    record = {"VulnerabilityID": "CVE-2024-0001", "PkgName": "a", "InstalledVersion": "1"}
    if raw is not None:
        record["Status"] = raw
    document = {"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": [record]}]}
    [finding] = parse_trivy_report(document, default_target="x").findings
    assert finding.vulnerability.status is expected


def test_skipped_records_are_counted() -> None:
    result = TrivyJsonSource(FIXTURES / "malformed.json").load()
    # Results[0] is not an object, and three vulnerability records are malformed.
    assert result.skipped == 4


def test_malformed_records_are_logged_and_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        findings = _load("malformed.json")
    assert [f.vulnerability.vuln_id for f in findings] == ["CVE-2023-1000", "CVE-2023-1003"]
    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 5
    assert "Results[0]" in warnings[0]
    assert "Vulnerabilities[1]" in warnings[1]
    assert "PkgName" in warnings[1]
    assert "not a valid CVE ID" in warnings[2]
    assert "ignoring out-of-range CVSS score 12.0 from nvd" in warnings[3]
    assert "Vulnerabilities[4]" in warnings[4]


def test_an_invalid_optional_field_does_not_drop_the_finding() -> None:
    """One bad CVSS value must not cost the whole finding (it may be in KEV)."""
    finding = _load("malformed.json")[1]
    assert finding.vulnerability.vuln_id == "CVE-2023-1003"
    assert finding.vulnerability.cvss_score is None


def test_null_cvss_is_accepted() -> None:
    record = {
        "VulnerabilityID": "CVE-2024-0001",
        "PkgName": "a",
        "InstalledVersion": "1",
        "CVSS": None,
    }
    document = {"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": [record]}]}
    [finding] = parse_trivy_report(document, default_target="x").findings
    assert finding.vulnerability.cvss_score is None


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
    ).findings
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
