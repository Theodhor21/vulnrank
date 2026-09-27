"""SARIF 2.1.0 for GitHub code scanning.

Checked against GitHub's "SARIF support for code scanning" docs (2026-09): every result needs
a location; `partialFingerprints` prevent duplicate alerts across uploads; a rule's
`security-severity` (a 0-10 string) sets the label: > 9.0 critical, 7.0-8.9 high,
4.0-6.9 medium, 0.1-3.9 low. We map tiers onto those bands so the Security tab sorts by
vulnrank's priority rather than raw CVSS.
"""

import hashlib
import json
import re
from typing import TextIO

from vulnrank import __version__
from vulnrank.adapters.outputs import _format as fmt
from vulnrank.domain.models import ChangeState, Priority, Report, ScoredFinding
from vulnrank.domain.targets import image_repository

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Theodhor21/vulnrank"
FINGERPRINT_KEY = "vulnrankFinding/v1"

SECURITY_SEVERITY = {Priority.P1: "9.5", Priority.P2: "8.0", Priority.P3: "5.5", Priority.P4: "2.0"}
LEVEL = {Priority.P1: "error", Priority.P2: "error", Priority.P3: "warning", Priority.P4: "note"}
BASELINE_STATE = {
    ChangeState.NEW: "new",
    ChangeState.ESCALATED: "updated",
    ChangeState.IMPROVED: "updated",
    ChangeState.UNCHANGED: "unchanged",
}
# SARIF needs a region even when the "file" is a container image.
WHOLE_FILE = {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}

_UNSAFE_URI_CHARACTERS = re.compile(r"[^A-Za-z0-9._/-]")


def artifact_uri_for(target: str) -> str:
    """A relative path for a scan target, without its tag or digest.

    Dropping the tag keeps alerts attached to the same "file" across builds, and a raw
    `nginx:1.19` would otherwise parse as a URI scheme.
    """
    return _UNSAFE_URI_CHARACTERS.sub("-", image_repository(target)).lstrip("/")


class SarifReporter:
    def __init__(self, *, artifact_uri: str | None = None) -> None:
        self._artifact_uri = artifact_uri

    def write(self, report: Report, out: TextIO, *, limit: int | None = None) -> None:
        json.dump(self.to_document(report, limit), out, indent=2, ensure_ascii=False)
        out.write("\n")

    def to_document(self, report: Report, limit: int | None = None) -> dict[str, object]:
        findings = fmt.listed(report.findings, limit)
        rule_ids = list(dict.fromkeys(f.finding.vulnerability.vuln_id for f in findings))
        rule_index = {cve: index for index, cve in enumerate(rule_ids)}
        return {
            "$schema": SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "vulnrank",
                            "version": __version__,
                            "informationUri": INFORMATION_URI,
                            "rules": [_rule(cve, findings) for cve in rule_ids],
                        }
                    },
                    "results": [
                        self._result(rank, scored, rule_index)
                        for rank, scored in enumerate(findings, start=1)
                    ],
                }
            ],
        }

    def _result(
        self, rank: int, scored: ScoredFinding, rule_index: dict[str, int]
    ) -> dict[str, object]:
        finding = scored.finding
        cve = finding.vulnerability.vuln_id
        uri = self._artifact_uri or artifact_uri_for(finding.target)
        result: dict[str, object] = {
            "ruleId": cve,
            "ruleIndex": rule_index[cve],
            "level": LEVEL[scored.priority],
            "message": {
                "text": f"{scored.priority} {cve} in {fmt.component(scored)}: {scored.explanation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": WHOLE_FILE,
                    }
                }
            ],
            "partialFingerprints": {FINGERPRINT_KEY: _fingerprint(scored)},
            "properties": {
                "priority": str(scored.priority),
                "rank": rank,
                "epss": scored.enrichment.epss_score,
                "cvss": finding.vulnerability.cvss_score,
                "in_kev": scored.enrichment.in_kev,
                "fixed_version": finding.vulnerability.fixed_version,
                "target": finding.target,
                "component": finding.component.name,
                "version": finding.component.version,
            },
        }
        if scored.change is not None:
            result["baselineState"] = BASELINE_STATE[scored.change.state]
        return result


def _rule(cve: str, findings: tuple[ScoredFinding, ...]) -> dict[str, object]:
    most_urgent = min(
        (f.priority for f in findings if f.finding.vulnerability.vuln_id == cve),
        key=lambda priority: priority.rank,
    )
    return {
        "id": cve,
        "shortDescription": {"text": cve},
        "helpUri": fmt.advisory_url(cve),
        "properties": {
            "tags": ["security", "vulnerability"],
            "security-severity": SECURITY_SEVERITY[most_urgent],
        },
    }


def _fingerprint(scored: ScoredFinding) -> str:
    """Identity only, without the image tag, so alerts survive re-ranking and new builds."""
    target, name, version, vuln_id = scored.finding.key
    identity = "\x1f".join((image_repository(target), name, version, vuln_id))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
