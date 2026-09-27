"""Choose the FindingSource for a scan file."""

from enum import StrEnum
from pathlib import Path

from vulnrank.adapters._raw import read_json
from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource
from vulnrank.adapters.inputs.grype import GrypeJsonSource
from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource
from vulnrank.ports.sources import FindingSource, SourceError


class InputFormat(StrEnum):
    AUTO = "auto"
    TRIVY = "trivy"
    CYCLONEDX = "cyclonedx"
    GRYPE = "grype"


def open_source(path: Path, input_format: InputFormat = InputFormat.AUTO) -> FindingSource:
    if input_format is InputFormat.AUTO:
        input_format = _detect(read_json(path), path)
    if input_format is InputFormat.CYCLONEDX:
        return CycloneDxSource(path)
    if input_format is InputFormat.GRYPE:
        return GrypeJsonSource(path)
    return TrivyJsonSource(path)


def _detect(document: object, path: Path) -> InputFormat:
    if isinstance(document, dict):
        if "bomFormat" in document:
            return InputFormat.CYCLONEDX
        if "SchemaVersion" in document:
            return InputFormat.TRIVY
        if "matches" in document and "descriptor" in document:
            return InputFormat.GRYPE
    raise SourceError(
        f"cannot tell the format of {path}: expected a Trivy or Grype JSON report or a "
        "CycloneDX JSON SBOM (use --input-format to choose explicitly)"
    )
