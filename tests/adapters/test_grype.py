import logging
from pathlib import Path

import pytest

from vulnrank.adapters.inputs.grype import GrypeJsonSource, parse_grype_report
from vulnrank.domain.models import Finding, FixStatus, Severity
from vulnrank.ports.sources import FindingSource, SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "grype"


def _load(name: str) -> list[Finding]:
    source: FindingSource = GrypeJsonSource(FIXTURES / name)
    return list(source.load().findings)


def test_matches_become_findings() -> None:
    keys = [(f.component.name, f.vulnerability.vuln_id) for f in _load("basic.json")]
    assert keys == [
        ("openssl", "CVE-2023-0001"),
        ("libssl3", "CVE-2023-0002"),
        ("openssl", "CVE-2023-0002"),
        ("requests", "CVE-2023-0003"),
        ("urllib3", "GHSA-aaaa-bbbb-cccc"),
    ]


def test_the_image_name_is_the_target() -> None:
    assert {f.target for f in _load("basic.json")} == {"demo-app:1.0"}


def test_a_directory_scan_uses_its_path_as_the_target() -> None:
    assert _load("malformed.json")[0].target == "/src/app"


def test_an_advisory_is_filed_under_its_related_cve() -> None:
    assert _load("malformed.json")[0].vulnerability.vuln_id == "CVE-2023-2000"


def test_fix_versions_state_and_negligible_severity() -> None:
    first, second = _load("malformed.json")
    assert first.vulnerability.fixed_version == "2.0.1, 1.9.9"
    assert first.vulnerability.status is FixStatus.FIXED
    assert first.vulnerability.severity is Severity.LOW  # "Negligible"
    assert first.vulnerability.cvss_score == 4.0  # no source given
    assert second.vulnerability.status is FixStatus.WILL_NOT_FIX
    assert second.vulnerability.fixed_version is None
    assert second.component.ecosystem == "apk"  # no purl: the artifact type


def test_malformed_matches_are_logged_skipped_and_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        result = GrypeJsonSource(FIXTURES / "malformed.json").load()
    assert result.skipped == 3
    assert "matches[2]" in caplog.text
    assert "matches[3]" in caplog.text
    assert "matches[4]" in caplog.text


@pytest.mark.parametrize(
    "document",
    [{"matches": []}, {"descriptor": {"name": "grype"}}, {"SchemaVersion": 2}],
    ids=["no-descriptor", "no-matches", "trivy"],
)
def test_other_documents_are_a_source_error(document: object) -> None:
    with pytest.raises(SourceError, match="not a Grype JSON report"):
        parse_grype_report(document, default_target="x")


def test_cvss_v2_scores_are_ignored() -> None:
    match = {
        "vulnerability": {
            "id": "CVE-2024-0001",
            "cvss": [{"source": "nvd@nist.gov", "version": "2.0", "metrics": {"baseScore": 10.0}}],
        },
        "artifact": {"name": "a", "version": "1"},
    }
    document = {"matches": [match], "descriptor": {"name": "grype"}}
    [finding] = parse_grype_report(document, default_target="x").findings
    assert finding.vulnerability.cvss_score is None


def test_bad_optional_fields_never_drop_a_match() -> None:
    """One broken CVSS entry, a null fix or null related list must not cost the finding."""
    result = GrypeJsonSource(FIXTURES / "odd.json").load()
    assert result.skipped == 0
    assert [f.vulnerability.vuln_id for f in result.findings] == [
        "CVE-2019-17543",
        "CVE-2024-0002",
        "CVE-2024-0003",
    ]
    lz4, second, third = result.findings
    assert lz4.vulnerability.cvss_score == 8.1  # NVD score listed under the related CVE
    assert second.vulnerability.cvss_score == 6.5  # the only valid entry
    assert second.vulnerability.fixed_version is None
    assert third.vulnerability.cvss_score is None
