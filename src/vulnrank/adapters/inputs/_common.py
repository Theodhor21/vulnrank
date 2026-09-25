"""Helpers shared by the input adapters, so both formats normalise data the same way."""

from typing import NamedTuple

from vulnrank.domain.models import Severity

_SEVERITY_ALIASES = {"info": Severity.LOW, "none": Severity.LOW}


class CvssCandidate(NamedTuple):
    source: str
    major_version: int
    score: float


def is_cve(identifier: str) -> bool:
    return identifier.strip().upper().startswith("CVE-")


def parse_severity(value: str | None) -> Severity:
    normalised = (value or "").strip().lower()
    if normalised in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[normalised]
    try:
        return Severity(normalised)
    except ValueError:
        return Severity.UNKNOWN


def pick_cvss(candidates: list[CvssCandidate]) -> float | None:
    """Prefer CVSS v3 over v4 (thresholds are v3-calibrated), and NVD over other sources."""
    for major in (3, 4):
        matching = sorted(
            (c for c in candidates if c.major_version == major),
            key=lambda c: (c.source != "nvd", c.source),
        )
        if matching:
            return matching[0].score
    return None


def ecosystem_from_purl(purl: str | None) -> str | None:
    """`pkg:deb/debian/openssl@3.0.9` -> `deb`."""
    if not purl or not purl.startswith("pkg:"):
        return None
    package_type = purl[len("pkg:") :].split("/", 1)[0]
    return package_type or None
