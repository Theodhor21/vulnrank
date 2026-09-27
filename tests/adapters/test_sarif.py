"""SARIF 2.1.0 output for GitHub code scanning.

Requirements checked against GitHub's "SARIF support for code scanning" docs (2026-09):
results need a location, partialFingerprints avoid duplicate alerts across uploads, and a
rule's `security-severity` (0-10 string) sets the critical/high/medium/low label.
"""

import io
import json
from typing import Any

import pytest

from tests.builders import make_asset, make_enrichment, make_finding
from vulnrank import __version__
from vulnrank.adapters.outputs.sarif import SarifReporter, artifact_uri_for
from vulnrank.domain.models import Criticality, Priority, Report, ScoredFinding
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import rank, score
from vulnrank.ports.reporting import Reporter


def _scored(
    *,
    cve: str,
    component: str = "openssl",
    target: str = "app:1.0",
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool = False,
    fixed: str | None = None,
) -> ScoredFinding:
    return score(
        make_finding(
            vuln_id=cve, component=component, target=target, cvss=cvss, fixed_version=fixed
        ),
        make_enrichment(epss=epss, in_kev=kev),
        make_asset(criticality=Criticality.HIGH, target=target),
        ScoringPolicy(),
    )


def _report(*findings: ScoredFinding) -> Report:
    return Report(findings=tuple(rank(findings)), scanned=len(findings), duplicates_removed=0)


REPORT = _report(
    _scored(cve="CVE-2024-0001", kev=True, fixed="1.1"),  # P1
    _scored(cve="CVE-2024-0002", cvss=9.8),  # P2 (CVSS >= 9 on a high asset)
    _scored(cve="CVE-2024-0002", component="libssl", cvss=7.5),  # same CVE, P3
    _scored(cve="CVE-2024-0003"),  # P4
)


def _sarif(
    report: Report = REPORT, *, limit: int | None = None, uri: str | None = None
) -> dict[str, Any]:
    reporter: Reporter = SarifReporter(artifact_uri=uri)
    out = io.StringIO()
    reporter.write(report, out, limit=limit)
    return json.loads(out.getvalue())


def _run(document: dict[str, Any]) -> dict[str, Any]:
    [run] = document["runs"]
    return run


# --- Document and tool ---------------------------------------------------------------------


def test_document_header() -> None:
    document = _sarif()
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1


def test_tool_driver() -> None:
    driver = _run(_sarif())["tool"]["driver"]
    assert driver["name"] == "vulnrank"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/Theodhor21/vulnrank"


# --- Rules: one per CVE ------------------------------------------------------------------------


def test_one_rule_per_cve_in_ranked_order() -> None:
    rules = _run(_sarif())["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]


def test_rule_links_to_nvd_and_is_tagged_security() -> None:
    rule = _run(_sarif())["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
    assert rule["shortDescription"]["text"] == "CVE-2024-0001"
    assert "security" in rule["properties"]["tags"]


def test_security_severity_follows_the_most_urgent_tier_of_the_cve() -> None:
    rules = _run(_sarif())["tool"]["driver"]["rules"]
    severity = {rule["id"]: rule["properties"]["security-severity"] for rule in rules}
    # GitHub labels: > 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
    assert severity == {
        "CVE-2024-0001": "9.5",  # P1 -> critical
        "CVE-2024-0002": "8.0",  # P2 beats its P3 sibling -> high
        "CVE-2024-0003": "2.0",  # P4 -> low
    }


# --- Results: one per finding -----------------------------------------------------------------


def test_one_result_per_finding_pointing_at_its_rule() -> None:
    run = _run(_sarif())
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(results) == 4
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


@pytest.mark.parametrize(
    ("priority", "level"),
    [
        (Priority.P1, "error"),
        (Priority.P2, "error"),
        (Priority.P3, "warning"),
        (Priority.P4, "note"),
    ],
)
def test_level_follows_the_tier(priority: Priority, level: str) -> None:
    results = _run(_sarif())["results"]
    matching = [r for r in results if r["properties"]["priority"] == priority]
    assert matching
    assert {r["level"] for r in matching} == {level}


def test_message_explains_the_decision() -> None:
    first = _run(_sarif())["results"][0]
    assert first["message"]["text"] == (
        "P1 CVE-2024-0001 in openssl 1.0.0: in CISA KEV; fix available (1.0.0 → 1.1)"
    )


def test_result_properties_carry_the_enrichment() -> None:
    first = _run(_sarif())["results"][0]
    assert first["properties"] == {
        "priority": "P1",
        "rank": 1,
        "epss": None,
        "cvss": None,
        "in_kev": True,
        "fixed_version": "1.1",
        "target": "app:1.0",
        "component": "openssl",
        "version": "1.0.0",
    }


# --- Locations and fingerprints -----------------------------------------------------------------


def test_location_defaults_to_a_path_derived_from_the_target() -> None:
    location = _run(_sarif())["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app"
    assert location["region"] == {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}


def test_location_can_point_at_a_repository_file() -> None:
    results = _run(_sarif(uri="deploy/Dockerfile"))["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"deploy/Dockerfile"}


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        # The tag or digest is dropped so alerts stay stable across builds.
        ("nginx:1.19", "nginx"),
        ("ghcr.io/org/app:1.2", "ghcr.io/org/app"),
        ("localhost:5000/app:1.2", "localhost-5000/app"),
        ("bkimminich/juice-shop", "bkimminich/juice-shop"),
        ("/abs/path to/scan.json", "abs/path-to/scan.json"),
        ("app@sha256:abc", "app"),
    ],
)
def test_artifact_uri_for_target(target: str, expected: str) -> None:
    assert artifact_uri_for(target) == expected


def test_fingerprints_are_stable_and_unique_per_finding() -> None:
    first = [r["partialFingerprints"] for r in _run(_sarif())["results"]]
    again = [r["partialFingerprints"] for r in _run(_sarif())["results"]]
    assert first == again
    values = [fp["vulnrankFinding/v1"] for fp in first]
    assert len(set(values)) == len(values)


def test_fingerprint_ignores_rank_and_enrichment() -> None:
    """Same CVE/component/target must keep its fingerprint when EPSS or ranking changes."""
    before = _sarif(_report(_scored(cve="CVE-2024-0009", epss=0.01)))
    after = _sarif(_report(_scored(cve="CVE-2024-0001"), _scored(cve="CVE-2024-0009", epss=0.9)))
    fingerprint_before = _run(before)["results"][0]["partialFingerprints"]
    [fingerprint_after] = [
        r["partialFingerprints"] for r in _run(after)["results"] if r["ruleId"] == "CVE-2024-0009"
    ]
    assert fingerprint_before == fingerprint_after


def test_fingerprint_and_location_survive_a_new_image_tag() -> None:
    """A new build (my-app:abc -> my-app:def) must update alerts, not close and reopen them."""
    old = _run(_sarif(_report(_scored(cve="CVE-2024-0001", target="my-app:abc123"))))
    new = _run(_sarif(_report(_scored(cve="CVE-2024-0001", target="my-app:def456"))))
    assert old["results"][0]["partialFingerprints"] == new["results"][0]["partialFingerprints"]
    assert old["results"][0]["locations"] == new["results"][0]["locations"]


def test_non_cve_rules_link_to_their_advisory() -> None:
    rules = _run(_sarif(_report(_scored(cve="GHSA-jfh8-c2jp-5v3q"))))["tool"]["driver"]["rules"]
    assert rules[0]["helpUri"] == "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"


# --- Limits and edge cases --------------------------------------------------------------------


def test_limit_caps_results_and_only_their_rules_are_listed() -> None:
    run = _run(_sarif(limit=1))
    assert [r["ruleId"] for r in run["results"]] == ["CVE-2024-0001"]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["CVE-2024-0001"]


def test_empty_report_is_still_a_valid_run() -> None:
    run = _run(_sarif(_report()))
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
