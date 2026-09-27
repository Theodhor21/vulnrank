from datetime import date

import pytest

from tests.builders import make_asset, make_enrichment, make_finding
from vulnrank.domain.models import Finding, FixStatus, ScoredFinding, VexAnalysis
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import score
from vulnrank.domain.suppression import (
    IgnoreRule,
    VexStatement,
    VexStatus,
    apply_suppressions,
)

TODAY = date(2026, 9, 28)
OPENSSL = "pkg:deb/debian/openssl@3.0.9-1?arch=amd64&distro=debian-12.1"


def _scored(finding: Finding, *, in_kev: bool = False) -> ScoredFinding:
    return score(finding, make_enrichment(in_kev=in_kev), make_asset(), ScoringPolicy())


def _rule(**kwargs: object) -> IgnoreRule:
    return IgnoreRule.model_validate({"reason": "accepted risk", "source": "assets.toml", **kwargs})


A = _scored(make_finding(vuln_id="CVE-2024-0001", component="openssl", purl=OPENSSL))
B = _scored(make_finding(vuln_id="CVE-2024-0002", component="openssl", purl=OPENSSL))
C = _scored(make_finding(vuln_id="CVE-2024-0001", component="linux-libc-dev", target="api:2"))
ALL = (A, B, C)


def _suppressed_ids(
    *, rules: tuple[IgnoreRule, ...] = (), statements: tuple[VexStatement, ...] = ()
) -> list[tuple[str, str]]:
    result = apply_suppressions(ALL, rules=rules, statements=statements, today=TODAY)
    return [
        (s.scored.finding.vulnerability.vuln_id, s.scored.finding.component.name)
        for s in result.suppressed
    ]


# --- Ignore rules (assets.toml [[ignore]] and .trivyignore) --------------------------------------


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        pytest.param(
            {"vuln_id": "CVE-2024-0001"},
            [("CVE-2024-0001", "openssl"), ("CVE-2024-0001", "linux-libc-dev")],
            id="by-id",
        ),
        pytest.param(
            {"package": "linux-libc-*"}, [("CVE-2024-0001", "linux-libc-dev")], id="by-package-glob"
        ),
        pytest.param(
            {"vuln_id": "CVE-2024-0001", "package": "openssl"},
            [("CVE-2024-0001", "openssl")],
            id="id-and-package",
        ),
        pytest.param(
            {"vuln_id": "CVE-2024-0001", "target": "api"},
            [("CVE-2024-0001", "linux-libc-dev")],
            id="target-without-tag",
        ),
    ],
)
def test_ignore_rules_match_by_id_package_and_target(
    rule: dict[str, object], expected: list[tuple[str, str]]
) -> None:
    assert _suppressed_ids(rules=(_rule(**rule),)) == expected


def test_suppressed_findings_leave_the_list_and_carry_the_reason() -> None:
    result = apply_suppressions(ALL, rules=(_rule(vuln_id="CVE-2024-0002"),), today=TODAY)
    assert result.kept == (A, C)
    [suppressed] = result.suppressed
    assert (suppressed.reason, suppressed.source) == ("accepted risk", "assets.toml")


def test_a_rule_applies_until_the_end_of_its_expiry_day() -> None:
    rule = _rule(vuln_id="CVE-2024-0002", expires=TODAY)
    assert len(apply_suppressions(ALL, rules=(rule,), today=TODAY).suppressed) == 1


def test_an_expired_rule_no_longer_applies_and_is_reported() -> None:
    rule = _rule(vuln_id="CVE-2024-0002", expires=date(2026, 9, 27))
    result = apply_suppressions(ALL, rules=(rule,), today=TODAY)
    assert result.suppressed == ()
    assert result.expired == (rule,)


def test_a_rule_needs_an_id_or_a_package() -> None:
    with pytest.raises(ValueError, match="needs an id or a package"):
        _rule(target="api")


# --- OpenVEX statements ----------------------------------------------------------------------


def _statement(**kwargs: object) -> VexStatement:
    fields = {"vuln_ids": ("CVE-2024-0001",), "status": "not_affected", "source": "vex.json"}
    return VexStatement.model_validate({**fields, **kwargs})


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        pytest.param(
            {},
            [("CVE-2024-0001", "openssl"), ("CVE-2024-0001", "linux-libc-dev")],
            id="no-products",
        ),
        pytest.param(
            {"products": ("pkg:deb/debian/openssl",)},
            [("CVE-2024-0001", "openssl")],
            id="purl-without-version-matches-any-version",
        ),
        pytest.param(
            {"products": ("pkg:deb/debian/openssl@3.0.9-1",)},
            [("CVE-2024-0001", "openssl")],
            id="purl-with-version-ignores-qualifiers",
        ),
        pytest.param({"products": ("pkg:deb/debian/openssl@3.0.8-1",)}, [], id="other-version"),
        pytest.param(
            {"vuln_ids": ("GHSA-aaaa-bbbb-cccc", "CVE-2024-0002")},
            [("CVE-2024-0002", "openssl")],
            id="alias",
        ),
        pytest.param({"status": "affected"}, [], id="affected-is-kept"),
        pytest.param({"status": "under_investigation"}, [], id="under-investigation-is-kept"),
    ],
)
def test_vex_statements(statement: dict[str, object], expected: list[tuple[str, str]]) -> None:
    assert _suppressed_ids(statements=(_statement(**statement),)) == expected


@pytest.mark.parametrize(
    ("status", "justification", "reason"),
    [
        (
            VexStatus.NOT_AFFECTED,
            "vulnerable_code_not_in_execute_path",
            "VEX: not_affected (vulnerable_code_not_in_execute_path)",
        ),
        (VexStatus.FIXED, None, "VEX: fixed"),
    ],
)
def test_vex_reason(status: VexStatus, justification: str | None, reason: str) -> None:
    statement = _statement(status=status, justification=justification)
    result = apply_suppressions((A,), statements=(statement,), today=TODAY)
    assert result.suppressed[0].reason == reason


# --- Statements inside the scan ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "suppressed"),
    [
        ("not_affected", True),
        ("false_positive", True),
        ("resolved", True),
        ("resolved_with_pedigree", True),
        ("exploitable", False),
        ("in_triage", False),
    ],
)
def test_cyclonedx_analysis_in_the_scan(state: str, suppressed: bool) -> None:
    finding = make_finding(analysis=VexAnalysis(state=state, justification="code_not_reachable"))
    result = apply_suppressions((_scored(finding),), today=TODAY)
    assert bool(result.suppressed) is suppressed
    if suppressed:
        assert result.suppressed[0].reason == f"CycloneDX analysis: {state} (code_not_reachable)"
        assert result.suppressed[0].source == "scan"


def test_vendor_status_not_affected() -> None:
    finding = make_finding(status=FixStatus.NOT_AFFECTED)
    [suppressed] = apply_suppressions((_scored(finding),), today=TODAY).suppressed
    assert (suppressed.reason, suppressed.source) == ("vendor status: not affected", "scan")


def test_the_scans_own_statement_wins_over_rules() -> None:
    finding = make_finding(status=FixStatus.NOT_AFFECTED)
    rule = _rule(vuln_id="CVE-2024-0001")
    [suppressed] = apply_suppressions((_scored(finding),), rules=(rule,), today=TODAY).suppressed
    assert suppressed.source == "scan"


def test_suppressing_a_known_exploited_finding_is_flagged() -> None:
    exploited = _scored(make_finding(), in_kev=True)
    result = apply_suppressions((exploited,), rules=(_rule(vuln_id="CVE-2024-0001"),), today=TODAY)
    assert result.suppressed[0].in_kev is True
