"""Tunable thresholds for the scoring rules."""

from typing import Self

from pydantic import model_validator

from vulnrank.domain.models import CvssScore, DomainModel, Probability


class ScoringPolicy(DomainModel):
    """Thresholds are inclusive (score >= threshold). Defaults are a sensible starting point."""

    p1_epss_on_high_criticality: Probability = 0.5
    p1_epss_on_exposed_critical: Probability = 0.1
    p2_epss: Probability = 0.1
    p2_cvss_on_high_criticality: CvssScore = 9.0
    p3_cvss: CvssScore = 7.0

    @model_validator(mode="after")
    def _tiers_are_consistent(self) -> Self:
        """A higher tier must not have a lower bar than the tier below it.

        The exposure rule is exempt: it is deliberately the most permissive P1 rule.
        """
        pairs = [
            (
                "p1_epss_on_high_criticality",
                self.p1_epss_on_high_criticality,
                "p2_epss",
                self.p2_epss,
            ),
            (
                "p2_cvss_on_high_criticality",
                self.p2_cvss_on_high_criticality,
                "p3_cvss",
                self.p3_cvss,
            ),
        ]
        for higher, higher_value, lower, lower_value in pairs:
            if higher_value < lower_value:
                raise ValueError(f"{higher} ({higher_value}) must be ≥ {lower} ({lower_value})")
        return self
