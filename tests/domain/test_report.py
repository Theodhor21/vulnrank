from tests.builders import make_scored
from vulnrank.domain.models import Priority, Report


def _report(*priorities: Priority) -> Report:
    findings = tuple(
        make_scored(priority=p, cve_id=f"CVE-2024-{i:04d}") for i, p in enumerate(priorities)
    )
    return Report(findings=findings, scanned=len(findings), duplicates_removed=0)


def test_counts_include_every_tier() -> None:
    report = _report(Priority.P1, Priority.P3, Priority.P3)
    assert report.counts == {Priority.P1: 1, Priority.P2: 0, Priority.P3: 2, Priority.P4: 0}


def test_threshold_check() -> None:
    report = _report(Priority.P2, Priority.P4)
    assert report.has_findings_at_or_above(Priority.P2)
    assert report.has_findings_at_or_above(Priority.P3)
    assert not report.has_findings_at_or_above(Priority.P1)
    assert not _report().has_findings_at_or_above(Priority.P4)


def test_targets_are_unique_and_sorted() -> None:
    assert _report(Priority.P1, Priority.P2).targets == ("app:1.0",)
    assert _report().targets == ()
