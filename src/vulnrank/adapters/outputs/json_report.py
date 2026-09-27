"""Machine-readable JSON with a versioned schema, for CI and other tools."""

import json
from typing import TextIO

from vulnrank.adapters.outputs._format import listed
from vulnrank.domain.models import Report, ScoredFinding, Suppressed
from vulnrank.domain.remediation import FixAction, plan_fixes

# 2: "cve" became "id" (advisories without a CVE are kept); added fix_status, skipped,
#    enrichment_issues, fix_plan and suppressed.
SCHEMA_VERSION = 2


class JsonReporter:
    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        json.dump(to_document(report, limit), out, indent=2, ensure_ascii=False)
        out.write("\n")


def to_document(report: Report, limit: int | None = None) -> dict[str, object]:
    findings = listed(report.findings, limit)
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "scanned": report.scanned,
            "skipped": report.skipped,
            "duplicates_removed": report.duplicates_removed,
            "unique_findings": len(report.findings),
            "listed": len(findings),
            "by_priority": {str(priority): count for priority, count in report.counts.items()},
            "targets": list(report.targets),
            "enrichment_issues": list(report.enrichment_issues),
            "suppressed": len(report.suppressed),
        },
        "findings": [_finding(rank, scored) for rank, scored in enumerate(findings, start=1)],
        "fix_plan": _fix_plan(report, limit),
        "suppressed": [_suppressed(s) for s in report.suppressed],
    }


def _suppressed(suppressed: Suppressed) -> dict[str, object]:
    finding = suppressed.scored.finding
    return {
        "id": finding.vulnerability.vuln_id,
        "target": finding.target,
        "component": finding.component.name,
        "version": finding.component.version,
        "priority": str(suppressed.scored.priority),
        "in_kev": suppressed.in_kev,
        "reason": suppressed.reason,
        "source": suppressed.source,
    }


def _fix_plan(report: Report, limit: int | None) -> dict[str, object]:
    plan = plan_fixes(report.findings)
    actions = listed(plan.actions, limit)
    return {
        "actions": [_action(rank, action) for rank, action in enumerate(actions, start=1)],
        "total_actions": len(plan.actions),
        "unfixable": {"count": len(plan.unfixable), "by_status": plan.unfixable_by_status},
    }


def _action(rank: int, action: FixAction) -> dict[str, object]:
    return {
        "rank": rank,
        "priority": str(action.priority),
        "target": action.target,
        "packages": list(action.packages),
        "installed_version": action.installed_version,
        "fixed_version": action.fixed_version,
        "vulnerabilities": list(action.vuln_ids),
        "by_priority": {str(p): n for p, n in action.counts.items()},
        "in_kev": action.kev_count,
    }


def _finding(rank: int, scored: ScoredFinding) -> dict[str, object]:
    vulnerability = scored.finding.vulnerability
    enrichment = scored.enrichment
    added = enrichment.kev_date_added
    return {
        "rank": rank,
        "priority": str(scored.priority),
        "id": vulnerability.vuln_id,
        "target": scored.finding.target,
        "component": scored.finding.component.model_dump(),
        "severity": str(vulnerability.severity),
        "cvss": vulnerability.cvss_score,
        "epss": enrichment.epss_score,
        "epss_percentile": enrichment.epss_percentile,
        "in_kev": enrichment.in_kev,
        "kev_date_added": added.isoformat() if added else None,
        "fixed_version": vulnerability.fixed_version,
        "fix_status": str(vulnerability.status) if vulnerability.status else None,
        "asset": {
            "criticality": str(scored.asset.criticality),
            "internet_exposed": scored.asset.internet_exposed,
        },
        "reasons": [
            {"text": reason.text, "decisive": reason.tier is not None} for reason in scored.reasons
        ],
    }
