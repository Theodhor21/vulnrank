"""Read OpenVEX documents (https://github.com/openvex/spec, v0.2.0; v0.0.x string form too)."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Self

from pydantic import Field, ValidationError, model_validator

from vulnrank.adapters._raw import RawModel, describe, read_json
from vulnrank.domain.suppression import VexProduct, VexStatement, VexStatus
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
    products: list[_Product | str] = Field(default_factory=list[_Product | str])
    justification: str | None = None
    impact_statement: str | None = None
    timestamp: datetime | None = None

    @model_validator(mode="after")
    def _not_affected_says_why(self) -> Self:
        """The spec requires a justification or an impact statement for not_affected."""
        if self.status is VexStatus.NOT_AFFECTED and not (
            self.justification or self.impact_statement
        ):
            raise ValueError("not_affected needs a justification or an impact_statement")
        return self


class _Document(RawModel):
    context: str = Field(alias="@context")
    timestamp: datetime | None = None
    statements: list[object]


def load_openvex(path: Path) -> tuple[VexStatement, ...]:
    try:
        document = _Document.model_validate(read_json(path))
    except ValidationError as exc:
        raise SourceError(f"{path} is not an OpenVEX document ({describe(exc)})") from exc
    statements: list[VexStatement] = []
    for index, raw in enumerate(document.statements):
        try:
            statement = _Statement.model_validate(raw)
            statements.append(_to_statement(statement, path.name, document.timestamp))
        except ValidationError as exc:
            logger.warning(
                "skipping malformed VEX statement %s statements[%d]: %s", path, index, describe(exc)
            )
    return tuple(statements)


def _to_statement(
    statement: _Statement, source: str, document_timestamp: datetime | None
) -> VexStatement:
    vulnerability = statement.vulnerability
    if isinstance(vulnerability, str):
        vuln_ids = (vulnerability,)
    else:
        vuln_ids = (vulnerability.name, *vulnerability.aliases)
    return VexStatement(
        vuln_ids=vuln_ids,
        status=statement.status,
        products=tuple(_product(product) for product in statement.products),
        justification=statement.justification or statement.impact_statement,
        timestamp=statement.timestamp or document_timestamp,
        source=source,
    )


def _product(product: _Product | str) -> VexProduct:
    if isinstance(product, str):
        return VexProduct(purl=product)  # OpenVEX v0.0.x
    subcomponents = tuple(purl for c in product.subcomponents if (purl := c.purl))
    return VexProduct(purl=product.purl, subcomponents=subcomponents)
