"""Read Grype's JSON report (`grype <image> -o json`).

Checked against real Grype 0.119 output: `matches[]` each hold a `vulnerability` (id,
severity, cvss[], fix), `relatedVulnerabilities` (a GHSA match lists its CVE here) and the
`artifact`. Grype's own EPSS/KEV/risk fields are ignored: vulnrank enriches every input the
same way.
"""

import logging
from pathlib import Path

from pydantic import Field, ValidationError

from vulnrank.adapters._raw import RawModel, describe, read_json
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
    base_score: float = Field(alias="baseScore")


class _Cvss(RawModel):
    source: str | None = None
    version: str = ""
    metrics: _Metrics

    @property
    def candidate(self) -> CvssCandidate | None:
        major = self.version.split(".", 1)[0]
        if major not in ("3", "4"):
            return None
        source = "nvd" if "nvd" in (self.source or "") else self.source or ""
        return CvssCandidate(source, int(major), self.metrics.base_score)


class _Fix(RawModel):
    versions: list[str] = Field(default_factory=list[str])
    state: str | None = None


class _Vulnerability(RawModel):
    id: str
    severity: str | None = None
    cvss: list[_Cvss] = Field(default_factory=list[_Cvss])
    fix: _Fix = Field(default_factory=_Fix)


class _Related(RawModel):
    id: str


class _Artifact(RawModel):
    name: str
    version: str = ""
    type: str | None = None
    purl: str | None = None


class _Match(RawModel):
    vulnerability: _Vulnerability
    related: list[_Related] = Field(default_factory=list[_Related], alias="relatedVulnerabilities")
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
    vulnerability, artifact = match.vulnerability, match.artifact
    candidates = [c for cvss in vulnerability.cvss if (c := cvss.candidate) is not None]
    return Finding(
        component=Component(
            name=artifact.name,
            version=artifact.version,
            purl=artifact.purl,
            ecosystem=ecosystem_from_purl(artifact.purl) or artifact.type,
        ),
        vulnerability=Vulnerability(
            vuln_id=_advisory_id(match),
            severity=parse_severity(vulnerability.severity),
            cvss_score=pick_cvss(candidates, vulnerability.id),
            fixed_version=", ".join(vulnerability.fix.versions) or None,
            status=FIX_STATES.get(vulnerability.fix.state or ""),
        ),
        target=target,
    )


def _advisory_id(match: _Match) -> str:
    """A GHSA match lists its CVE under relatedVulnerabilities; prefer the CVE."""
    if is_cve(match.vulnerability.id):
        return match.vulnerability.id
    return next((r.id for r in match.related if is_cve(r.id)), match.vulnerability.id)
