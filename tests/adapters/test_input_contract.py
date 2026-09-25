"""Both input formats describe the same scan in `basic.json`; they must agree exactly."""

from pathlib import Path

from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource
from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource
from vulnrank.domain.models import Finding

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: finding.key)


def test_trivy_and_cyclonedx_yield_equivalent_findings() -> None:
    trivy = TrivyJsonSource(FIXTURES / "trivy" / "basic.json").load()
    cyclonedx = CycloneDxSource(FIXTURES / "cyclonedx" / "basic.json").load()
    assert len(trivy) == 4
    assert _sorted(trivy) == _sorted(cyclonedx)
