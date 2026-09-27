"""Core domain models: plain validated data, no behaviour that touches the outside world."""

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,12}")
# Other advisory databases: GHSA-xxxx-xxxx-xxxx, PYSEC-2021-19, GO-2022-0493, ...
_ADVISORY_ID = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{2,62}")


def _normalise_cve_id(value: str) -> str:
    normalised = value.strip().upper()
    if not _CVE_ID.fullmatch(normalised):
        raise ValueError(f"not a valid CVE ID: {value!r}")
    return normalised


def _normalise_advisory_id(value: str) -> str:
    """CVE IDs are validated strictly; other IDs keep their case after an upper-case prefix."""
    stripped = value.strip()
    prefix, dash, rest = stripped.partition("-")
    if prefix.upper() == "CVE":
        return _normalise_cve_id(stripped)
    normalised = f"{prefix.upper()}{dash}{rest}"
    if not _ADVISORY_ID.fullmatch(normalised):
        raise ValueError(f"not a valid advisory ID: {value!r}")
    return normalised


CveId = Annotated[str, AfterValidator(_normalise_cve_id)]
AdvisoryId = Annotated[str, AfterValidator(_normalise_advisory_id)]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
CvssScore = Annotated[float, Field(ge=0.0, le=10.0)]
NonEmptyStr = Annotated[str, Field(min_length=1)]


class DomainModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Severity(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def is_at_least(self, other: Self) -> bool:
        members = list(type(self))
        return members.index(self) >= members.index(other)


class FixStatus(StrEnum):
    """The vendor's fix status, as Trivy reports it."""

    FIXED = "fixed"
    AFFECTED = "affected"
    WILL_NOT_FIX = "will_not_fix"
    FIX_DEFERRED = "fix_deferred"
    END_OF_LIFE = "end_of_life"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        """1 is the most urgent."""
        return int(self.value[1:])

    def is_at_least(self, other: Self) -> bool:
        """True if this priority is as urgent as `other` or more."""
        return self.rank <= other.rank


class Component(DomainModel):
    name: NonEmptyStr
    version: str
    purl: str | None = None
    ecosystem: str | None = None


class VexAnalysis(DomainModel):
    """A CycloneDX `analysis` block: the producer's own verdict on a vulnerability."""

    state: NonEmptyStr
    justification: str | None = None
    detail: str | None = None


class Vulnerability(DomainModel):
    vuln_id: AdvisoryId
    severity: Severity = Severity.UNKNOWN
    cvss_score: CvssScore | None = None
    fixed_version: str | None = None
    status: FixStatus | None = None
    analysis: VexAnalysis | None = None

    @property
    def fix_available(self) -> bool:
        return bool(self.fixed_version)

    @property
    def is_cve(self) -> bool:
        """EPSS and CISA KEV only cover CVE IDs."""
        return self.vuln_id.startswith("CVE-")


FindingKey = tuple[str, str, str, str]


class Finding(DomainModel):
    component: Component
    vulnerability: Vulnerability
    target: NonEmptyStr

    @property
    def key(self) -> FindingKey:
        """Identity used for deduplication: same advisory in the same component and target."""
        return (
            self.target,
            self.component.name,
            self.component.version,
            self.vulnerability.vuln_id,
        )


class ScanResult(DomainModel):
    """What an input adapter produced: valid findings plus how many records it had to skip."""

    findings: tuple[Finding, ...]
    skipped: int = 0


class Asset(DomainModel):
    target: NonEmptyStr
    criticality: Criticality = Criticality.MEDIUM
    internet_exposed: bool = False


class EpssScore(DomainModel):
    score: Probability
    percentile: Probability


class KevEntry(DomainModel):
    cve_id: CveId
    date_added: date


class Enrichment(DomainModel):
    epss_score: Probability | None = None
    epss_percentile: Probability | None = None
    in_kev: bool = False
    kev_date_added: date | None = None


class Reason(DomainModel):
    """A human-readable justification. `tier` is set when the reason decided the priority."""

    text: NonEmptyStr
    tier: Priority | None = None


class ScoredFinding(DomainModel):
    finding: Finding
    enrichment: Enrichment
    asset: Asset
    priority: Priority
    reasons: tuple[Reason, ...]

    @property
    def explanation(self) -> str:
        return "; ".join(reason.text for reason in self.reasons)


class Suppressed(DomainModel):
    """A finding left out of the ranking, and why."""

    scored: ScoredFinding
    reason: NonEmptyStr
    source: NonEmptyStr

    @property
    def in_kev(self) -> bool:
        return self.scored.enrichment.in_kev


class Report(DomainModel):
    """The outcome of one run: ranked findings plus what happened on the way."""

    findings: tuple[ScoredFinding, ...]
    scanned: int
    duplicates_removed: int
    skipped: int = 0
    enrichment_issues: tuple[str, ...] = ()
    suppressed: tuple[Suppressed, ...] = ()

    @property
    def counts(self) -> dict[Priority, int]:
        counts = dict.fromkeys(Priority, 0)
        for scored in self.findings:
            counts[scored.priority] += 1
        return counts

    @property
    def targets(self) -> tuple[str, ...]:
        return tuple(sorted({scored.finding.target for scored in self.findings}))

    def has_findings_at_or_above(self, threshold: Priority) -> bool:
        return any(scored.priority.is_at_least(threshold) for scored in self.findings)
