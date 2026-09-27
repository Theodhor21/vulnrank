"""Helpers shared by the input adapters, so both formats normalise data the same way."""

import logging
from typing import NamedTuple

from vulnrank.domain.models import Severity

logger = logging.getLogger(__name__)

_SEVERITY_ALIASES = {"info": Severity.LOW, "none": Severity.LOW, "negligible": Severity.LOW}


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


def pick_cvss(candidates: list[CvssCandidate], context: str = "") -> float | None:
    """Prefer CVSS v3 over v4 (thresholds are v3-calibrated), and NVD over other sources.

    An out-of-range score is ignored with a warning rather than dropping the whole finding.
    """
    candidates = [c for c in candidates if _in_range(c, context)]
    for major in (3, 4):
        matching = sorted(
            (c for c in candidates if c.major_version == major),
            key=lambda c: (c.source != "nvd", c.source),
        )
        if matching:
            return matching[0].score
    return None


def _in_range(candidate: CvssCandidate, context: str) -> bool:
    if 0.0 <= candidate.score <= 10.0:
        return True
    suffix = f" for {context}" if context else ""
    logger.warning(
        "ignoring out-of-range CVSS score %s from %s%s", candidate.score, candidate.source, suffix
    )
    return False


def ecosystem_from_purl(purl: str | None) -> str | None:
    """`pkg:deb/debian/openssl@3.0.9` -> `deb`."""
    if not purl or not purl.startswith("pkg:"):
        return None
    package_type = purl[len("pkg:") :].split("/", 1)[0]
    return package_type or None
