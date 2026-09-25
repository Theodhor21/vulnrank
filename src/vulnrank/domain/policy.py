"""Tunable thresholds for the scoring rules."""

from vulnrank.domain.models import CvssScore, DomainModel, Probability


class ScoringPolicy(DomainModel):
    """Thresholds are inclusive (score >= threshold). Defaults are a sensible starting point."""

    p1_epss_on_high_criticality: Probability = 0.5
    p1_epss_on_exposed_critical: Probability = 0.1
    p2_epss: Probability = 0.1
    p2_cvss_on_high_criticality: CvssScore = 9.0
    p3_cvss: CvssScore = 7.0
