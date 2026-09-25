"""Small factories so each test states only the fields it cares about."""

from datetime import date

from vulnrank.domain.models import (
    Asset,
    Component,
    Criticality,
    Enrichment,
    Finding,
    Priority,
    Reason,
    ScoredFinding,
    Vulnerability,
)


def make_finding(
    *,
    cve_id: str = "CVE-2024-0001",
    cvss: float | None = None,
    fixed_version: str | None = None,
    component: str = "openssl",
    version: str = "1.0.0",
    target: str = "app:1.0",
) -> Finding:
    return Finding(
        component=Component(name=component, version=version),
        vulnerability=Vulnerability(cve_id=cve_id, cvss_score=cvss, fixed_version=fixed_version),
        target=target,
    )


def make_enrichment(
    *, epss: float | None = None, in_kev: bool = False, kev_date_added: date | None = None
) -> Enrichment:
    return Enrichment(epss_score=epss, in_kev=in_kev, kev_date_added=kev_date_added)


def make_asset(
    *,
    criticality: Criticality = Criticality.MEDIUM,
    internet_exposed: bool = False,
    target: str = "app:1.0",
) -> Asset:
    return Asset(target=target, criticality=criticality, internet_exposed=internet_exposed)


def make_scored(
    *,
    priority: Priority,
    epss: float | None = None,
    cvss: float | None = None,
    fixed_version: str | None = None,
    cve_id: str = "CVE-2024-0001",
) -> ScoredFinding:
    return ScoredFinding(
        finding=make_finding(cve_id=cve_id, cvss=cvss, fixed_version=fixed_version),
        enrichment=make_enrichment(epss=epss),
        asset=make_asset(),
        priority=priority,
        reasons=(Reason(text="test", tier=priority),),
    )
