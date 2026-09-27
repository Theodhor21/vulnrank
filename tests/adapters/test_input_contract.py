"""Each fixture pair describes the same scan in both formats; they must agree exactly."""

from pathlib import Path

import pytest

from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource
from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource
from vulnrank.domain.models import Finding

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: finding.key)


@pytest.mark.parametrize(
    ("name", "count"),
    [
        pytest.param("basic.json", 4, id="basic"),
        # CycloneDX splits `@scope/pkg` (npm) and `group:artifact` (Maven) into group + name.
        pytest.param("grouped.json", 2, id="scoped-and-maven-packages"),
    ],
)
def test_trivy_and_cyclonedx_yield_equivalent_findings(name: str, count: int) -> None:
    trivy = TrivyJsonSource(FIXTURES / "trivy" / name).load()
    cyclonedx = CycloneDxSource(FIXTURES / "cyclonedx" / name).load()
    assert len(trivy) == count
    assert _sorted(trivy) == _sorted(cyclonedx)


def test_grouped_package_names_keep_their_group() -> None:
    findings = CycloneDxSource(FIXTURES / "cyclonedx" / "grouped.json").load()
    assert {(f.component.name, f.vulnerability.fixed_version) for f in findings} == {
        ("@scope/once", "2.0.1"),
        ("org.example.logging:logging-core", "2.17.1"),
    }
