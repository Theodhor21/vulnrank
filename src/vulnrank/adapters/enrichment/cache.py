"""A tiny on-disk cache: one JSON file of timestamped entries, with a TTL."""

import json
import logging
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
DEFAULT_TTL = timedelta(hours=24)


def utc_now() -> datetime:
    return datetime.now(UTC)


def default_cache_dir(environ: Mapping[str, str] = os.environ) -> Path:
    """`$XDG_CACHE_HOME/vulnrank`, falling back to `~/.cache/vulnrank`."""
    base = environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vulnrank"


class CacheEntry(NamedTuple):
    value: object
    fetched_at: datetime


class _StoredEntry(BaseModel):
    value: object
    fetched_at: datetime


class _CacheFile(BaseModel):
    version: int = 1
    entries: dict[str, _StoredEntry] = {}


class JsonCache:
    def __init__(self, path: Path, *, ttl: timedelta = DEFAULT_TTL, clock: Clock = utc_now) -> None:
        self._path = path
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[str, _StoredEntry] | None = None

    def get(self, key: str) -> CacheEntry | None:
        stored = self._load().get(key)
        return CacheEntry(stored.value, stored.fetched_at) if stored else None

    def is_fresh(self, entry: CacheEntry) -> bool:
        return self._clock() - entry.fetched_at < self._ttl

    def put_many(self, values: Mapping[str, object]) -> None:
        if not values:
            return
        now = self._clock()
        entries = self._load()
        entries.update({key: _StoredEntry(value=v, fetched_at=now) for key, v in values.items()})
        self._write(entries)

    def _load(self) -> dict[str, _StoredEntry]:
        if self._entries is None:
            self._entries = self._read()
        return self._entries

    def _read(self) -> dict[str, _StoredEntry]:
        try:
            return _CacheFile.model_validate_json(self._path.read_bytes()).entries
        except FileNotFoundError:
            return {}
        except (OSError, ValidationError) as exc:
            logger.warning("ignoring unreadable cache file %s: %s", self._path, exc)
            return {}

    def _write(self, entries: dict[str, _StoredEntry]) -> None:
        document = _CacheFile(entries=entries).model_dump(mode="json")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(".tmp")
            temporary.write_text(json.dumps(document), encoding="utf-8")
            temporary.replace(self._path)
        except OSError as exc:
            logger.warning("could not write cache file %s: %s", self._path, exc)
