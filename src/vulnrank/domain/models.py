"""Core domain models: plain validated data, no behaviour that touches the outside world."""

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def _normalise_cve_id(value: str) -> str:
    normalised = value.strip().upper()
    if not _CVE_ID.fullmatch(normalised):
        raise ValueError(f"not a valid CVE ID: {value!r}")
    return normalised


CveId = Annotated[str, AfterValidator(_normalise_cve_id)]
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


class Vulnerability(DomainModel):
    cve_id: CveId
    severity: Severity = Severity.UNKNOWN
    cvss_score: CvssScore | None = None
    fixed_version: str | None = None

    @property
    def fix_available(self) -> bool:
        return bool(self.fixed_version)


FindingKey = tuple[str, str, str, str]


class Finding(DomainModel):
    component: Component
    vulnerability: Vulnerability
    target: NonEmptyStr

    @property
    def key(self) -> FindingKey:
        """Identity used for deduplication: same CVE in the same component and target."""
        return (
            self.target,
            self.component.name,
            self.component.version,
            self.vulnerability.cve_id,
        )


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
