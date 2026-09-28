"""Parsing helpers for third-party JSON, shared by every adapter."""

import codecs
import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnrank.ports.sources import SourceError

_UTF16_BOMS = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)


def decode_text(raw: bytes, source: object) -> str:
    """UTF-8 (with or without a BOM) or UTF-16 with a BOM, which PowerShell's `>` writes."""
    try:
        if raw.startswith(_UTF16_BOMS):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError(
            f"{source} is not valid UTF-8 or UTF-16 text ({exc.reason} at byte {exc.start})"
        ) from exc


def read_text(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc.strerror}") from exc
    return decode_text(raw, path)


def read_json(path: Path) -> object:
    text = read_text(path)
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


def valid_items[M: BaseModel](model: type[M], items: Iterable[object] | None) -> list[M]:
    """The items that validate as `model`; invalid optional entries are simply left out.

    For optional sub-fields (a CVSS entry, a rating, a related advisory): one bad entry must
    never cost the whole finding.
    """
    valid: list[M] = []
    for item in items or ():
        try:
            valid.append(model.model_validate(item))
        except ValidationError:
            continue
    return valid


def valid_or_none[M: BaseModel](model: type[M], item: object) -> M | None:
    [*found] = valid_items(model, [item] if item is not None else [])
    return found[0] if found else None
