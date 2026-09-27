"""Each fixture pair describes the same scan in both formats; they must agree exactly."""

from pathlib import Path

import pytest

from vulnrank.adapters.inputs.cyclonedx import CycloneDxSource
from vulnrank.adapters.inputs.grype import GrypeJsonSource
from vulnrank.adapters.inputs.trivy_json import TrivyJsonSource
from vulnrank.domain.models import Finding

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _comparable(findings: tuple[Finding, ...]) -> list[Finding]:
    """CycloneDX has no field for Trivy's vendor fix status, so leave it out of the comparison."""
    return sorted(
        (
            f.model_copy(
                update={"vulnerability": f.vulnerability.model_copy(update={"status": None})}
            )
            for f in findings
        ),
        key=lambda finding: finding.key,
    )


@pytest.mark.parametrize(
    ("name", "count"),
    [
        pytest.param("basic.json", 5, id="basic"),
        # CycloneDX splits `@scope/pkg` (npm) and `group:artifact` (Maven) into group + name.
        pytest.param("grouped.json", 2, id="scoped-and-maven-packages"),
    ],
)
def test_trivy_and_cyclonedx_yield_equivalent_findings(name: str, count: int) -> None:
    trivy = TrivyJsonSource(FIXTURES / "trivy" / name).load().findings
    cyclonedx = CycloneDxSource(FIXTURES / "cyclonedx" / name).load().findings
    assert len(trivy) == count
    assert _comparable(trivy) == _comparable(cyclonedx)


def test_grouped_package_names_keep_their_group() -> None:
    findings = CycloneDxSource(FIXTURES / "cyclonedx" / "grouped.json").load().findings
    assert {(f.component.name, f.vulnerability.fixed_version) for f in findings} == {
        ("@scope/once", "2.0.1"),
        ("org.example.logging:logging-core", "2.17.1"),
    }


def test_trivy_and_grype_yield_identical_findings_including_fix_status() -> None:
    trivy = TrivyJsonSource(FIXTURES / "trivy" / "basic.json").load().findings
    grype = GrypeJsonSource(FIXTURES / "grype" / "basic.json").load().findings
    assert sorted(trivy, key=lambda f: f.key) == sorted(grype, key=lambda f: f.key)
