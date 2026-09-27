"""Read an earlier vulnrank JSON report (schema 2) as a baseline."""

import logging
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from vulnrank.adapters._raw import RawModel, describe, read_json
from vulnrank.domain.baseline import Baseline, BaselineKey
from vulnrank.domain.models import Priority
from vulnrank.domain.targets import image_repository
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)


class _Summary(RawModel):
    listed: int
    unique_findings: int


class _Component(RawModel):
    name: str


class _Entry(RawModel):
    id: str
    target: str
    component: _Component
    priority: Priority


class _Report(RawModel):
    schema_version: Literal[2]
    summary: _Summary
    findings: list[object]


def load_baseline(path: Path) -> Baseline:
    try:
        report = _Report.model_validate(read_json(path))
    except ValidationError as exc:
        message = f"{path} is not a vulnrank JSON report (schema 2): {describe(exc)}"
        raise SourceError(message) from exc
    priorities: dict[BaselineKey, Priority] = {}
    for index, raw in enumerate(report.findings):
        try:
            entry = _Entry.model_validate(raw)
        except ValidationError as exc:
            logger.warning(
                "skipping baseline entry %s findings[%d]: %s", path, index, describe(exc)
            )
            continue
        key = (image_repository(entry.target), entry.component.name, entry.id)
        priorities[key] = entry.priority
    complete = report.summary.listed >= report.summary.unique_findings
    return Baseline(priorities=priorities, complete=complete)
