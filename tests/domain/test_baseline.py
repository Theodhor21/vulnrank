from tests.builders import make_scored
from vulnrank.domain.baseline import Baseline, ChangeState, baseline_key, compare_to_baseline
from vulnrank.domain.models import Priority, Report

P1, P2, P3, P4 = Priority.P1, Priority.P2, Priority.P3, Priority.P4


def _baseline(**entries: Priority) -> Baseline:
    return Baseline(
        priorities={
            ("app", "openssl", vuln_id.replace("_", "-")): p for vuln_id, p in entries.items()
        }
    )


def test_the_key_ignores_the_image_tag() -> None:
    scored = make_scored(priority=P1, target="registry.io/app:2.0", component="zlib")
    assert baseline_key(scored.finding) == ("registry.io/app", "zlib", "CVE-2024-0001")


def test_findings_are_new_escalated_unchanged_or_improved() -> None:
    findings = [
        make_scored(priority=P1, vuln_id="CVE-2024-0001"),  # was P3: escalated
        make_scored(priority=P2, vuln_id="CVE-2024-0002"),  # was P2: unchanged
        make_scored(priority=P4, vuln_id="CVE-2024-0003"),  # was P1: improved
        make_scored(priority=P3, vuln_id="CVE-2024-0004"),  # not there: new
    ]
    baseline = _baseline(CVE_2024_0001=P3, CVE_2024_0002=P2, CVE_2024_0003=P1, CVE_2024_0009=P2)
    result = compare_to_baseline(findings, baseline)
    changes = [(s.change.state, s.change.previous) for s in result.findings if s.change]
    assert changes == [
        (ChangeState.ESCALATED, P3),
        (ChangeState.UNCHANGED, P2),
        (ChangeState.IMPROVED, P1),
        (ChangeState.NEW, None),
    ]
    assert result.resolved == 1  # CVE-2024-0009 is gone


def test_with_a_baseline_only_new_or_escalated_findings_trip_the_gate() -> None:
    old_p1 = make_scored(priority=P1, vuln_id="CVE-2024-0001")
    new_p3 = make_scored(priority=P3, vuln_id="CVE-2024-0002")
    result = compare_to_baseline([old_p1, new_p3], _baseline(CVE_2024_0001=P1))
    report = Report(findings=result.findings, scanned=2, duplicates_removed=0, baseline_resolved=0)
    assert not report.has_findings_at_or_above(P1)
    assert report.has_findings_at_or_above(P3)


def test_without_a_baseline_every_finding_counts() -> None:
    report = Report(findings=(make_scored(priority=P1),), scanned=1, duplicates_removed=0)
    assert report.has_findings_at_or_above(P1)
    assert report.baseline_resolved is None
