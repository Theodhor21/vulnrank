"""Leave findings out of the ranking on purpose, and say why.

Three kinds of statements can suppress a finding, checked in this order:

1. the scan's own verdict: a CycloneDX `analysis` (not_affected, false_positive, resolved) or
   Trivy's vendor status `not_affected`;
2. VEX statements (OpenVEX) saying `not_affected` or `fixed`;
3. ignore rules (from assets.toml or .trivyignore), matched by advisory ID, package glob and
   target glob, until their expiry date.

Suppressed findings are reported separately, never silently dropped.
"""

import re
from collections.abc import Iterable
from datetime import UTC, date, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Annotated, Self

from pydantic import AliasChoices, BeforeValidator, Field, field_validator, model_validator

from vulnrank.domain.models import (
    DomainModel,
    FixStatus,
    NonEmptyStr,
    ScoredFinding,
    Suppressed,
    normalise_advisory_id,
)
from vulnrank.domain.targets import image_repository

SUPPRESSING_ANALYSIS = frozenset(
    {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}
)
SCAN = "scan"


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


SUPPRESSING_VEX = frozenset({VexStatus.NOT_AFFECTED, VexStatus.FIXED})
_EARLIEST = datetime.min.replace(tzinfo=UTC)


def canonical_id(vuln_id: str) -> str:
    """`cve-2024-1` -> `CVE-2024-1`, as scan IDs are normalised; anything else stays as given."""
    try:
        return normalise_advisory_id(vuln_id)
    except ValueError:
        return vuln_id.strip()


class IgnoreRule(DomainModel):
    """Accept a risk: by advisory ID, package name glob, or both; optionally per target."""

    vuln_id: str | None = Field(default=None, validation_alias=AliasChoices("vuln_id", "id"))
    package: str | None = None
    target: str | None = None
    reason: NonEmptyStr
    expires: date | None = None
    source: NonEmptyStr = "config"

    @field_validator("vuln_id")
    @classmethod
    def _canonical_id(cls, vuln_id: str | None) -> str | None:
        return canonical_id(vuln_id) if vuln_id else vuln_id

    @model_validator(mode="after")
    def _has_a_subject(self) -> Self:
        if not (self.vuln_id or self.package):
            raise ValueError("an ignore rule needs an id or a package")
        return self

    @property
    def label(self) -> str:
        return self.vuln_id or f"package {self.package}"

    def is_active(self, today: date) -> bool:
        """A rule applies up to and including its expiry day."""
        return self.expires is None or today <= self.expires

    def matches(self, scored: ScoredFinding) -> bool:
        finding = scored.finding
        if self.vuln_id and self.vuln_id != finding.vulnerability.vuln_id:
            return False
        if self.package and not fnmatchcase(finding.component.name, self.package):
            return False
        return not self.target or _target_matches(self.target, finding.target)


class VexProduct(DomainModel):
    """An OpenVEX product: a purl, optionally narrowed to some of its subcomponents."""

    purl: str | None = None
    subcomponents: tuple[str, ...] = ()

    def matches(self, scored: ScoredFinding) -> bool:
        finding = scored.finding
        if self.purl is not None and not self.purl.startswith("pkg:oci/"):
            return _purl_matches(self.purl, finding.component.purl)  # a package product
        if self.purl is not None and not _image_matches(self.purl, finding.target):
            return False  # a statement about another image
        if not self.subcomponents:
            return True
        return any(_purl_matches(p, finding.component.purl) for p in self.subcomponents)


def _purl_as_product(value: object) -> object:
    """OpenVEX v0.0.x lists products as plain purl strings."""
    return {"purl": value} if isinstance(value, str) else value


ProductOrPurl = Annotated[VexProduct, BeforeValidator(_purl_as_product)]


class VexStatement(DomainModel):
    """One OpenVEX statement. No products means it applies to every product."""

    vuln_ids: tuple[str, ...]  # the vulnerability name and its aliases
    status: VexStatus
    products: tuple[ProductOrPurl, ...] = ()
    justification: str | None = None
    timestamp: datetime | None = None
    source: NonEmptyStr

    @field_validator("vuln_ids")
    @classmethod
    def _canonical_ids(cls, vuln_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(canonical_id(vuln_id) for vuln_id in vuln_ids)

    @property
    def reason(self) -> str:
        suffix = f" ({self.justification})" if self.justification else ""
        return f"VEX: {self.status}{suffix}"

    def matches(self, scored: ScoredFinding) -> bool:
        if scored.finding.vulnerability.vuln_id not in self.vuln_ids:
            return False
        return not self.products or any(product.matches(scored) for product in self.products)


class SuppressionResult(DomainModel):
    kept: tuple[ScoredFinding, ...]
    suppressed: tuple[Suppressed, ...]
    expired: tuple[IgnoreRule, ...]


def apply_suppressions(
    findings: Iterable[ScoredFinding],
    *,
    rules: tuple[IgnoreRule, ...] = (),
    statements: tuple[VexStatement, ...] = (),
    today: date,
) -> SuppressionResult:
    active = [rule for rule in rules if rule.is_active(today)]
    kept: list[ScoredFinding] = []
    suppressed: list[Suppressed] = []
    for scored in findings:
        verdict = (
            _scan_verdict(scored)
            or _vex_verdict(scored, statements)
            or _rule_verdict(scored, active)
        )
        if verdict is None:
            kept.append(scored)
        else:
            reason, source = verdict
            suppressed.append(Suppressed(scored=scored, reason=reason, source=source))
    expired = tuple(rule for rule in rules if not rule.is_active(today))
    return SuppressionResult(kept=tuple(kept), suppressed=tuple(suppressed), expired=expired)


def _scan_verdict(scored: ScoredFinding) -> tuple[str, str] | None:
    vulnerability = scored.finding.vulnerability
    analysis = vulnerability.analysis
    if analysis is not None and analysis.state in SUPPRESSING_ANALYSIS:
        suffix = f" ({analysis.justification})" if analysis.justification else ""
        return f"CycloneDX analysis: {analysis.state}{suffix}", SCAN
    if vulnerability.status is FixStatus.NOT_AFFECTED:
        return "vendor status: not affected", SCAN
    return None


def _vex_verdict(
    scored: ScoredFinding, statements: tuple[VexStatement, ...]
) -> tuple[str, str] | None:
    """The latest matching statement decides (by timestamp, then by order of appearance)."""
    matching = [(index, s) for index, s in enumerate(statements) if s.matches(scored)]
    if not matching:
        return None
    _, latest = max(matching, key=lambda item: (item[1].timestamp or _EARLIEST, item[0]))
    if latest.status not in SUPPRESSING_VEX:
        return None
    return latest.reason, latest.source


def _rule_verdict(scored: ScoredFinding, rules: list[IgnoreRule]) -> tuple[str, str] | None:
    rule = next((r for r in rules if r.matches(scored)), None)
    return None if rule is None else (rule.reason, rule.source)


def _target_matches(pattern: str, target: str) -> bool:
    return fnmatchcase(target, pattern) or fnmatchcase(image_repository(target), pattern)


_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


def _purl_base(purl: str) -> str:
    """A purl without qualifiers or subpath, percent-decoded.

    `pkg:deb/debian/openssl@1.1.1d-0%2Bdeb10u6?arch=amd64`
    -> `pkg:deb/debian/openssl@1.1.1d-0+deb10u6`
    """
    without_extras = re.split(r"[?#]", purl, maxsplit=1)[0]
    return _PERCENT.sub(lambda m: chr(int(m.group(1), 16)), without_extras)


def _purl_matches(statement_purl: str, component_purl: str | None) -> bool:
    """A statement purl without a version matches every version of the package."""
    if component_purl is None:
        return False
    wanted, actual = _purl_base(statement_purl), _purl_base(component_purl)
    if "@" in wanted:
        return wanted == actual
    return actual.partition("@")[0] == wanted


def _image_matches(oci_purl: str, target: str) -> bool:
    """`pkg:oci/demo-app` names the image `demo-app` (any registry, tag or digest)."""
    name = _purl_base(oci_purl).removeprefix("pkg:oci/").partition("@")[0]
    return image_repository(target).rsplit("/", 1)[-1] == name
