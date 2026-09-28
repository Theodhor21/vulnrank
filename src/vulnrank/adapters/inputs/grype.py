"""Read Grype's JSON report (`grype <image> -o json`).

Checked against real Grype 0.119 output: `matches[]` each hold a `vulnerability` (id,
severity, cvss[], fix), `relatedVulnerabilities` (a GHSA match lists its CVE here) and the
`artifact`. Grype's own EPSS/KEV/risk fields are ignored: vulnrank enriches every input the
same way.
"""

import logging
from pathlib import Path

from pydantic import Field, ValidationError

from vulnrank.adapters._raw import RawModel, describe, read_json, valid_items, valid_or_none
from vulnrank.adapters.inputs._common import (
    CvssCandidate,
    ecosystem_from_purl,
    is_cve,
    parse_severity,
    pick_cvss,
)
from vulnrank.domain.models import Component, Finding, FixStatus, ScanResult, Vulnerability
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)

FIX_STATES = {
    "fixed": FixStatus.FIXED,
    "not-fixed": FixStatus.AFFECTED,
    "wont-fix": FixStatus.WILL_NOT_FIX,
}


class _Metrics(RawModel):
    base_score: float | None = Field(default=None, alias="baseScore")


class _Cvss(RawModel):
    source: str | None = None
    version: str = ""
    metrics: _Metrics | None = None

    @property
    def candidate(self) -> CvssCandidate | None:
        major = self.version.split(".", 1)[0]
        if major not in ("3", "4") or self.metrics is None or self.metrics.base_score is None:
            return None
        source = "nvd" if "nvd" in (self.source or "") else self.source or ""
        return CvssCandidate(source, int(major), self.metrics.base_score)


class _Fix(RawModel):
    versions: list[str] = Field(default_factory=list[str])
    state: str | None = None


class _Vulnerability(RawModel):
    id: str
    severity: str | None = None
    cvss: list[object] | None = None  # validated entry by entry
    fix: object | None = None


class _Related(RawModel):
    id: str
    cvss: list[object] | None = None


class _Artifact(RawModel):
    name: str
    version: str = ""
    type: str | None = None
    purl: str | None = None


class _Match(RawModel):
    vulnerability: _Vulnerability
    related: list[object] | None = Field(default=None, alias="relatedVulnerabilities")
    artifact: _Artifact


class _ImageTarget(RawModel):
    user_input: str = Field(alias="userInput")


class _Source(RawModel):
    target: _ImageTarget | str | None = None


class _Descriptor(RawModel):
    name: str


class _Report(RawModel):
    matches: list[object]
    source: _Source | None = None
    descriptor: _Descriptor


class GrypeJsonSource:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> ScanResult:
        return parse_grype_report(read_json(self._path), default_target=self._path.name)


def parse_grype_report(document: object, *, default_target: str) -> ScanResult:
    try:
        report = _Report.model_validate(document)
    except ValidationError as exc:
        raise SourceError(f"not a Grype JSON report ({describe(exc)})") from exc
    target = _target(report) or default_target
    findings: list[Finding] = []
    for index, raw in enumerate(report.matches):
        try:
            findings.append(_to_finding(_Match.model_validate(raw), target))
        except ValidationError as exc:
            logger.warning("skipping malformed Grype match matches[%d]: %s", index, describe(exc))
    return ScanResult(findings=tuple(findings), skipped=len(report.matches) - len(findings))


def _target(report: _Report) -> str | None:
    target = report.source.target if report.source else None
    if isinstance(target, _ImageTarget):
        return target.user_input
    return target


def _to_finding(match: _Match, target: str) -> Finding:
    """Optional fields (CVSS entries, fix, related advisories) are read leniently."""
    vulnerability, artifact = match.vulnerability, match.artifact
    related = valid_items(_Related, match.related)
    # Grype often lists the NVD score only under the related CVE; read both.
    entries = [*(vulnerability.cvss or ()), *(e for r in related for e in r.cvss or ())]
    candidates = [c for cvss in valid_items(_Cvss, entries) if (c := cvss.candidate) is not None]
    fix = valid_or_none(_Fix, vulnerability.fix) or _Fix()
    return Finding(
        component=Component(
            name=artifact.name,
            version=artifact.version,
            purl=artifact.purl,
            ecosystem=ecosystem_from_purl(artifact.purl) or artifact.type,
        ),
        vulnerability=Vulnerability(
            vuln_id=_advisory_id(match, related),
            severity=parse_severity(vulnerability.severity),
            cvss_score=pick_cvss(candidates, vulnerability.id),
            fixed_version=", ".join(fix.versions) or None,
            status=FIX_STATES.get(fix.state or ""),
        ),
        target=target,
    )


def _advisory_id(match: _Match, related: list[_Related]) -> str:
    """A GHSA match lists its CVE under relatedVulnerabilities; prefer the CVE."""
    if is_cve(match.vulnerability.id):
        return match.vulnerability.id
    return next((r.id for r in related if is_cve(r.id)), match.vulnerability.id)
