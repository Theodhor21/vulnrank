from pathlib import Path

import pytest

from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource
from vulnrank.adapters.inputs.detect import InputFormat, open_source
from vulnrank.adapters.inputs.grype import GrypeJsonSource
from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource
from vulnrank.ports.sources import SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (FIXTURES / "trivy" / "basic.json", TrivyJsonSource),
        (FIXTURES / "cyclonedx" / "basic.json", CycloneDxSource),
        (FIXTURES / "grype" / "basic.json", GrypeJsonSource),
    ],
)
def test_format_is_detected_from_content(path: Path, expected: type) -> None:
    assert isinstance(open_source(path), expected)


def test_explicit_format_skips_detection(tmp_path: Path) -> None:
    path = tmp_path / "not-read-yet.json"
    assert isinstance(open_source(path, InputFormat.CYCLONEDX), CycloneDxSource)
    assert isinstance(open_source(path, InputFormat.TRIVY), TrivyJsonSource)
    assert isinstance(open_source(path, InputFormat.GRYPE), GrypeJsonSource)


@pytest.mark.parametrize("content", ['{"hello": 1}', "[1, 2]"])
def test_unknown_content_is_a_source_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "scan.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SourceError, match="--input-format"):
        open_source(path)
