"""Read Trivy's native JSON report (`trivy image --format json`)."""

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
from vulnrank.domain.models import Component, Finding, Vulnerability
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)


class _Cvss(RawModel):
    v3_score: float | None = Field(default=None, alias="V3Score")
    v40_score: float | None = Field(default=None, alias="V40Score")


class _PkgIdentifier(RawModel):
    purl: str | None = Field(default=None, alias="PURL")


class _Vulnerability(RawModel):
    vulnerability_id: str = Field(alias="VulnerabilityID")
    pkg_name: str = Field(alias="PkgName")
    installed_version: str = Field(default="", alias="InstalledVersion")
    fixed_version: str | None = Field(default=None, alias="FixedVersion")
    severity: str | None = Field(default=None, alias="Severity")
    pkg_identifier: _PkgIdentifier | None = Field(default=None, alias="PkgIdentifier")
    cvss: dict[str, _Cvss] = Field(default_factory=dict[str, _Cvss], alias="CVSS")


class _Result(RawModel):
    target: str = Field(alias="Target")
    type: str | None = Field(default=None, alias="Type")
    vulnerabilities: list[object] | None = Field(default=None, alias="Vulnerabilities")


class _Report(RawModel):
    schema_version: int = Field(alias="SchemaVersion")
    artifact_name: str | None = Field(default=None, alias="ArtifactName")
    results: list[object] = Field(default_factory=list[object], alias="Results")


class TrivyJsonSource:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> list[Finding]:
        return parse_trivy_report(read_json(self._path), default_target=self._path.name)


def parse_trivy_report(document: object, *, default_target: str) -> list[Finding]:
    try:
        report = _Report.model_validate(document)
    except ValidationError as exc:
        raise SourceError(f"not a Trivy JSON report ({describe(exc)})") from exc
    target = report.artifact_name or default_target
    findings: list[Finding] = []
    for index, raw_result in enumerate(report.results):
        findings.extend(_parse_result(raw_result, target, f"Results[{index}]"))
    return findings


def _parse_result(raw: object, target: str, where: str) -> list[Finding]:
    try:
        result = _Result.model_validate(raw)
    except ValidationError as exc:
        logger.warning("skipping malformed Trivy result %s: %s", where, describe(exc))
        return []
    findings: list[Finding] = []
    for index, raw_vulnerability in enumerate(result.vulnerabilities or []):
        location = f"{where}.Vulnerabilities[{index}]"
        finding = _parse_vulnerability(raw_vulnerability, result, target, location)
        if finding is not None:
            findings.append(finding)
    return findings


def _parse_vulnerability(raw: object, result: _Result, target: str, where: str) -> Finding | None:
    try:
        vulnerability = _Vulnerability.model_validate(raw)
        if not is_cve(vulnerability.vulnerability_id):
            logger.info(
                "skipping %s at %s: not a CVE ID (EPSS and KEV cover CVEs only)",
                vulnerability.vulnerability_id,
                where,
            )
            return None
        return _to_finding(vulnerability, result, target)
    except ValidationError as exc:
        logger.warning("skipping malformed Trivy vulnerability %s: %s", where, describe(exc))
        return None


def _to_finding(vulnerability: _Vulnerability, result: _Result, target: str) -> Finding:
    purl = vulnerability.pkg_identifier.purl if vulnerability.pkg_identifier else None
    return Finding(
        component=Component(
            name=vulnerability.pkg_name,
            version=vulnerability.installed_version,
            purl=purl,
            ecosystem=ecosystem_from_purl(purl) or result.type,
        ),
        vulnerability=Vulnerability(
            cve_id=vulnerability.vulnerability_id,
            severity=parse_severity(vulnerability.severity),
            cvss_score=pick_cvss(_cvss_candidates(vulnerability.cvss)),
            fixed_version=vulnerability.fixed_version or None,
        ),
        target=target,
    )


def _cvss_candidates(cvss: dict[str, _Cvss]) -> list[CvssCandidate]:
    candidates: list[CvssCandidate] = []
    for source, scores in cvss.items():
        if scores.v3_score is not None:
            candidates.append(CvssCandidate(source, 3, scores.v3_score))
        if scores.v40_score is not None:
            candidates.append(CvssCandidate(source, 4, scores.v40_score))
    return candidates
