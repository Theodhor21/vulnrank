"""Machine-readable JSON with a versioned schema, for CI and other tools."""

import json
from typing import TextIO

from vulnrank.adapters.outputs._format import listed
from vulnrank.domain.models import Report, ScoredFinding

SCHEMA_VERSION = 1


class JsonReporter:
    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        json.dump(to_document(report, limit), out, indent=2, ensure_ascii=False)
        out.write("\n")


def to_document(report: Report, limit: int | None = None) -> dict[str, object]:
    findings = listed(report, limit)
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "scanned": report.scanned,
            "duplicates_removed": report.duplicates_removed,
            "unique_findings": len(report.findings),
            "listed": len(findings),
            "by_priority": {str(priority): count for priority, count in report.counts.items()},
            "targets": list(report.targets),
        },
        "findings": [_finding(rank, scored) for rank, scored in enumerate(findings, start=1)],
    }


def _finding(rank: int, scored: ScoredFinding) -> dict[str, object]:
    vulnerability = scored.finding.vulnerability
    enrichment = scored.enrichment
    added = enrichment.kev_date_added
    return {
        "rank": rank,
        "priority": str(scored.priority),
        "cve": vulnerability.cve_id,
        "target": scored.finding.target,
        "component": scored.finding.component.model_dump(),
        "severity": str(vulnerability.severity),
        "cvss": vulnerability.cvss_score,
        "epss": enrichment.epss_score,
        "epss_percentile": enrichment.epss_percentile,
        "in_kev": enrichment.in_kev,
        "kev_date_added": added.isoformat() if added else None,
        "fixed_version": vulnerability.fixed_version,
        "asset": {
            "criticality": str(scored.asset.criticality),
            "internet_exposed": scored.asset.internet_exposed,
        },
        "reasons": [
            {"text": reason.text, "decisive": reason.tier is not None} for reason in scored.reasons
        ],
    }
