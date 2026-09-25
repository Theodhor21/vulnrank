"""Collapse repeated findings (e.g. the same package reported by several scanner layers)."""

from collections.abc import Iterable

from vulnrank.domain.models import Finding, FindingKey


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Keep the first finding per (target, component, version, CVE), preserving input order."""
    unique: dict[FindingKey, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.key, finding)
    return list(unique.values())
