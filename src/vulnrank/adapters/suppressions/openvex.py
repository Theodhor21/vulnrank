"""Read OpenVEX documents (https://github.com/openvex/spec, v0.2.0; v0.0.x string form too)."""

import logging
from pathlib import Path

from pydantic import Field, ValidationError

from vulnrank.adapters._raw import RawModel, describe, read_json
from vulnrank.domain.suppression import VexStatement, VexStatus
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)


class _Vulnerability(RawModel):
    name: str
    aliases: list[str] = Field(default_factory=list[str])


class _Component(RawModel):
    id: str | None = Field(default=None, alias="@id")
    identifiers: dict[str, str] = Field(default_factory=dict[str, str])

    @property
    def purl(self) -> str | None:
        return self.identifiers.get("purl") or self.id


class _Product(_Component):
    subcomponents: list[_Component] = Field(default_factory=list[_Component])


class _Statement(RawModel):
    vulnerability: _Vulnerability | str
    status: VexStatus
    products: list[_Product] = Field(default_factory=list[_Product])
    justification: str | None = None
    impact_statement: str | None = None


class _Document(RawModel):
    context: str = Field(alias="@context")
    statements: list[object]


def load_openvex(path: Path) -> tuple[VexStatement, ...]:
    try:
        document = _Document.model_validate(read_json(path))
    except ValidationError as exc:
        raise SourceError(f"{path} is not an OpenVEX document ({describe(exc)})") from exc
    statements: list[VexStatement] = []
    for index, raw in enumerate(document.statements):
        try:
            statements.append(_to_statement(_Statement.model_validate(raw), path.name))
        except ValidationError as exc:
            logger.warning(
                "skipping malformed VEX statement %s statements[%d]: %s", path, index, describe(exc)
            )
    return tuple(statements)


def _to_statement(statement: _Statement, source: str) -> VexStatement:
    vulnerability = statement.vulnerability
    if isinstance(vulnerability, str):
        vuln_ids = (vulnerability,)
    else:
        vuln_ids = (vulnerability.name, *vulnerability.aliases)
    purls = [
        purl
        for product in statement.products
        for component in (product, *product.subcomponents)
        if (purl := component.purl)
    ]
    return VexStatement(
        vuln_ids=vuln_ids,
        status=statement.status,
        products=tuple(purls),
        justification=statement.justification or statement.impact_statement,
        source=source,
    )
