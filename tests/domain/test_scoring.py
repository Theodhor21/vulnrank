from datetime import date

import pytest

from tests.builders import make_asset, make_enrichment, make_finding
from vulnrank.domain.models import Criticality, Priority, ScoredFinding
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.scoring import NO_RULE_MATCHED, score

C = Criticality
DEFAULT_POLICY = ScoringPolicy()


def _score(
    *,
    epss: float | None = None,
    cvss: float | None = None,
    in_kev: bool = False,
    criticality: Criticality = C.MEDIUM,
    exposed: bool = False,
    fixed_version: str | None = None,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ScoredFinding:
    return score(
        make_finding(cvss=cvss, fixed_version=fixed_version),
        make_enrichment(epss=epss, in_kev=in_kev),
        make_asset(criticality=criticality, internet_exposed=exposed),
        policy,
    )


def _decisive(scored: ScoredFinding) -> list[str]:
    return [reason.text for reason in scored.reasons if reason.tier is not None]


# --- P1 -----------------------------------------------------------------------------------


def test_kev_is_p1_regardless_of_asset() -> None:
    scored = _score(in_kev=True, criticality=C.LOW)
    assert scored.priority is Priority.P1
    assert _decisive(scored) == ["in CISA KEV"]


def test_kev_reason_includes_date_added_when_known() -> None:
    scored = score(
        make_finding(),
        make_enrichment(in_kev=True, kev_date_added=date(2021, 12, 10)),
        make_asset(),
        DEFAULT_POLICY,
    )
    assert _decisive(scored) == ["in CISA KEV (added 2021-12-10)"]


@pytest.mark.parametrize("criticality", [C.HIGH, C.CRITICAL])
def test_high_epss_on_high_or_critical_asset_is_p1(criticality: Criticality) -> None:
    scored = _score(epss=0.5, criticality=criticality)
    assert scored.priority is Priority.P1
    assert _decisive(scored) == [f"EPSS 50.0% ≥ 50.0% on a {criticality} asset"]


def test_moderate_epss_on_exposed_critical_asset_is_p1() -> None:
    scored = _score(epss=0.1, criticality=C.CRITICAL, exposed=True)
    assert scored.priority is Priority.P1
    assert _decisive(scored) == ["EPSS 10.0% ≥ 10.0% on an internet-exposed critical asset"]


def test_all_matching_p1_rules_are_reported() -> None:
    scored = _score(in_kev=True, epss=0.9, criticality=C.CRITICAL, exposed=True)
    assert _decisive(scored) == [
        "in CISA KEV",
        "EPSS 90.0% ≥ 50.0% on a critical asset",
        "EPSS 90.0% ≥ 10.0% on an internet-exposed critical asset",
    ]


# --- Boundaries between tiers -------------------------------------------------------------


@pytest.mark.parametrize(
    ("epss", "cvss", "criticality", "exposed", "expected"),
    [
        # High EPSS needs a high/critical asset and must reach the threshold.
        pytest.param(0.49, None, C.HIGH, False, Priority.P2, id="epss-just-below-p1"),
        pytest.param(0.9, None, C.MEDIUM, False, Priority.P2, id="high-epss-medium-asset"),
        # The exposure rule needs exposure AND a critical asset AND EPSS >= 0.1.
        pytest.param(0.1, None, C.HIGH, True, Priority.P2, id="exposed-but-only-high"),
        pytest.param(0.1, None, C.CRITICAL, False, Priority.P2, id="critical-not-exposed"),
        pytest.param(0.09, None, C.CRITICAL, True, Priority.P4, id="exposed-epss-too-low"),
        # CVSS >= 9.0 escalates to P2 only on high/critical assets.
        pytest.param(None, 9.0, C.HIGH, False, Priority.P2, id="cvss-9-high-asset"),
        pytest.param(None, 9.0, C.MEDIUM, False, Priority.P3, id="cvss-9-medium-asset"),
        pytest.param(None, 8.9, C.CRITICAL, False, Priority.P3, id="cvss-just-below-p2"),
        # CVSS >= 7.0 is P3 on any asset.
        pytest.param(None, 7.0, C.LOW, False, Priority.P3, id="cvss-7-low-asset"),
        pytest.param(None, 6.9, C.CRITICAL, False, Priority.P4, id="cvss-just-below-p3"),
        pytest.param(None, None, C.CRITICAL, True, Priority.P4, id="no-data"),
    ],
)
def test_tier_boundaries(
    epss: float | None,
    cvss: float | None,
    criticality: Criticality,
    exposed: bool,
    expected: Priority,
) -> None:
    scored = _score(epss=epss, cvss=cvss, criticality=criticality, exposed=exposed)
    assert scored.priority is expected


# --- P2, P3, P4 reasons --------------------------------------------------------------------


def test_elevated_epss_reason() -> None:
    assert _decisive(_score(epss=0.25)) == ["EPSS 25.0% ≥ 10.0%"]


def test_critical_cvss_on_important_asset_reason() -> None:
    assert _decisive(_score(cvss=9.8, criticality=C.HIGH)) == ["CVSS 9.8 ≥ 9.0 on a high asset"]


def test_high_cvss_reason() -> None:
    assert _decisive(_score(cvss=7.5)) == ["CVSS 7.5 ≥ 7.0"]


def test_p4_explains_that_nothing_matched() -> None:
    scored = _score(epss=0.01, cvss=5.0)
    assert scored.priority is Priority.P4
    assert _decisive(scored) == [NO_RULE_MATCHED]


def test_lower_tier_rules_are_not_listed_once_a_higher_tier_matches() -> None:
    scored = _score(in_kev=True, epss=0.3, cvss=9.8)
    assert _decisive(scored) == ["in CISA KEV"]


# --- Context reasons -----------------------------------------------------------------------


def test_fix_available_is_shown_with_versions() -> None:
    scored = _score(in_kev=True, exposed=True, fixed_version="1.0.9")
    assert scored.explanation == (
        "in CISA KEV; asset is internet-exposed; fix available (1.0.0 → 1.0.9)"
    )


def test_missing_fix_is_shown() -> None:
    assert _score().reasons[-1].text == "no fix available"


def test_fix_availability_does_not_change_tier() -> None:
    assert _score(cvss=7.5, fixed_version="2.0").priority is _score(cvss=7.5).priority


def test_context_reasons_have_no_tier() -> None:
    scored = _score(exposed=True)
    assert [reason.tier for reason in scored.reasons] == [Priority.P4, None, None]


# --- Policy ----------------------------------------------------------------------------------


def test_thresholds_come_from_the_policy() -> None:
    strict = ScoringPolicy(p2_epss=0.3, p3_cvss=8.0)
    assert _score(epss=0.2, policy=strict).priority is Priority.P4
    assert _score(cvss=7.5, policy=strict).priority is Priority.P4
    assert _decisive(_score(epss=0.3, policy=strict)) == ["EPSS 30.0% ≥ 30.0%"]


def test_scored_finding_keeps_its_inputs() -> None:
    finding = make_finding(cvss=7.5)
    enrichment = make_enrichment(epss=0.02)
    asset = make_asset()
    scored = score(finding, enrichment, asset, DEFAULT_POLICY)
    assert (scored.finding, scored.enrichment, scored.asset) == (finding, enrichment, asset)
