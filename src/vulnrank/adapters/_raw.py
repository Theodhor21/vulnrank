"""Parsing helpers for third-party JSON, shared by every adapter."""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnrank.ports.sources import SourceError


def read_json(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceError(f"{path} is not valid JSON: {exc}") from exc


class RawModel(BaseModel):
    """Lenient model for third-party JSON: unknown fields are ignored."""

    model_config = ConfigDict(extra="ignore")


def describe(exc: ValidationError) -> str:
    """One-line summary of a validation error, e.g. `PkgName: Field required`."""
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
        for error in exc.errors()
    )
