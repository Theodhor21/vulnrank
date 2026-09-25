"""Read a CycloneDX JSON SBOM that carries a `vulnerabilities` section.

Trivy produces one with `trivy image --scanners vuln --format cyclonedx`. CycloneDX has no
field for the fixed version, so it is taken from Trivy's recommendation text
("Upgrade <pkg> to version <x>") or, failing that, an `unaffected` version in `affects`.
"""

import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from vulnrank.adapters.inputs._common import (
    CvssCandidate,
    RawModel,
    describe,
    ecosystem_from_purl,
    is_cve,
    parse_severity,
    pick_cvss,
    read_json,
)
from vulnrank.domain.models import Component, Finding, Severity, Vulnerability
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)

_RECOMMENDATION = re.compile(r"Upgrade (?P<package>.+?) to version (?P<version>.+)")
_CVSS_METHOD_VERSIONS = {"CVSSv3": 3, "CVSSv31": 3, "CVSSv4": 4}


class _Source(RawModel):
    name: str | None = None


class _Rating(RawModel):
    source: _Source | None = None
    score: float | None = None
    severity: str | None = None
    method: str | None = None

    @property
    def source_name(self) -> str:
        return (self.source.name if self.source else None) or ""


class _AffectedVersion(RawModel):
    version: str | None = None
    status: str | None = None


class _Affects(RawModel):
    ref: str
    versions: list[_AffectedVersion] = Field(default_factory=list[_AffectedVersion])


class _Vulnerability(RawModel):
    id: str
    source: _Source | None = None
    ratings: list[_Rating] = Field(default_factory=list[_Rating])
    recommendation: str | None = None
    affects: list[_Affects] = Field(default_factory=list[_Affects])


class _Component(RawModel):
    bom_ref: str | None = Field(default=None, alias="bom-ref")
    name: str
    version: str = ""
    purl: str | None = None
    components: list[object] = Field(default_factory=list[object])


class _MetadataComponent(RawModel):
    name: str | None = None


class _Metadata(RawModel):
    component: _MetadataComponent | None = None


class _Bom(RawModel):
    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    metadata: _Metadata | None = None
    components: list[object] = Field(default_factory=list[object])
    vulnerabilities: list[object] | None = None


class CycloneDxSource:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> list[Finding]:
        return parse_cyclonedx(read_json(self._path), default_target=self._path.name)


def parse_cyclonedx(document: object, *, default_target: str) -> list[Finding]:
    try:
        bom = _Bom.model_validate(document)
    except ValidationError as exc:
        raise SourceError(f"not a CycloneDX JSON document ({describe(exc)})") from exc
    if bom.vulnerabilities is None:
        logger.warning(
            "the SBOM has no vulnerabilities section; with Trivy, generate it with "
            "`--scanners vuln`"
        )
        return []
    target = _target_name(bom) or default_target
    components = _index_components(bom.components, "components")
    findings: list[Finding] = []
    for index, raw in enumerate(bom.vulnerabilities):
        findings.extend(_parse_vulnerability(raw, components, target, f"vulnerabilities[{index}]"))
    return findings


def _target_name(bom: _Bom) -> str | None:
    if bom.metadata and bom.metadata.component:
        return bom.metadata.component.name
    return None


def _index_components(raw_components: list[object], where: str) -> dict[str, _Component]:
    return {
        component.bom_ref: component
        for component in _walk_components(raw_components, where)
        if component.bom_ref
    }


def _walk_components(raw_components: list[object], where: str) -> Iterator[_Component]:
    """Yield valid components depth-first; CycloneDX allows nesting."""
    for position, raw in enumerate(raw_components):
        location = f"{where}[{position}]"
        try:
            component = _Component.model_validate(raw)
        except ValidationError as exc:
            logger.warning("skipping malformed CycloneDX component %s: %s", location, describe(exc))
            continue
        yield component
        yield from _walk_components(component.components, f"{location}.components")


def _parse_vulnerability(
    raw: object, components: dict[str, _Component], target: str, where: str
) -> list[Finding]:
    try:
        vulnerability = _Vulnerability.model_validate(raw)
    except ValidationError as exc:
        logger.warning("skipping malformed CycloneDX vulnerability %s: %s", where, describe(exc))
        return []
    if not is_cve(vulnerability.id):
        logger.info(
            "skipping %s at %s: not a CVE ID (EPSS and KEV cover CVEs only)",
            vulnerability.id,
            where,
        )
        return []
    if not vulnerability.affects:
        logger.warning("skipping CycloneDX vulnerability %s: no affected components", where)
        return []
    findings: list[Finding] = []
    for position, affects in enumerate(vulnerability.affects):
        location = f"{where}.affects[{position}]"
        finding = _to_finding(vulnerability, affects, components, target, location)
        if finding is not None:
            findings.append(finding)
    return findings


def _to_finding(
    vulnerability: _Vulnerability,
    affects: _Affects,
    components: dict[str, _Component],
    target: str,
    where: str,
) -> Finding | None:
    component = components.get(affects.ref)
    if component is None:
        logger.warning("skipping %s: unknown component reference %r", where, affects.ref)
        return None
    try:
        return Finding(
            component=Component(
                name=component.name,
                version=component.version or _affected_version(affects) or "",
                purl=component.purl,
                ecosystem=ecosystem_from_purl(component.purl),
            ),
            vulnerability=Vulnerability(
                cve_id=vulnerability.id,
                severity=_severity(vulnerability),
                cvss_score=pick_cvss(_cvss_candidates(vulnerability.ratings)),
                fixed_version=_fixed_version(vulnerability, component, affects),
            ),
            target=target,
        )
    except ValidationError as exc:
        logger.warning("skipping malformed CycloneDX vulnerability %s: %s", where, describe(exc))
        return None


def _severity(vulnerability: _Vulnerability) -> Severity:
    """The rating from the vulnerability's own data source, else NVD, else the first one."""
    rated = [rating for rating in vulnerability.ratings if rating.severity]
    primary = vulnerability.source.name if vulnerability.source else None
    for preferred in (primary, "nvd"):
        for rating in rated:
            if rating.source_name == preferred:
                return parse_severity(rating.severity)
    return parse_severity(rated[0].severity) if rated else Severity.UNKNOWN


def _cvss_candidates(ratings: list[_Rating]) -> list[CvssCandidate]:
    candidates: list[CvssCandidate] = []
    for rating in ratings:
        major = _CVSS_METHOD_VERSIONS.get(rating.method or "")
        if major is not None and rating.score is not None:
            candidates.append(CvssCandidate(rating.source_name, major, rating.score))
    return candidates


def _fixed_version(
    vulnerability: _Vulnerability, component: _Component, affects: _Affects
) -> str | None:
    for part in (vulnerability.recommendation or "").split("; "):
        match = _RECOMMENDATION.fullmatch(part.strip())
        if match and match["package"] == component.name:
            return match["version"]
    for version in affects.versions:
        if version.status == "unaffected" and version.version:
            return version.version
    return None


def _affected_version(affects: _Affects) -> str | None:
    for version in affects.versions:
        if version.status == "affected" and version.version:
            return version.version
    return None
