"""Helpers shared by the input adapters, so both formats normalise data the same way."""

import json
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnrank.domain.models import Severity
from vulnrank.ports.sources import SourceError

_SEVERITY_ALIASES = {"info": Severity.LOW, "none": Severity.LOW}


class RawModel(BaseModel):
    """Lenient model for third-party JSON: unknown fields are ignored."""

    model_config = ConfigDict(extra="ignore")


class CvssCandidate(NamedTuple):
    source: str
    major_version: int
    score: float


def read_json(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceError(f"{path} is not valid JSON: {exc}") from exc


def describe(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
        for error in exc.errors()
    )


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
