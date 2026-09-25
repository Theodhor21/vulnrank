"""EPSS scores from the FIRST API (https://api.first.org/epss/) or a downloaded CSV.

API facts this relies on (checked against the FIRST docs, 2026-09):
- `cve` takes comma-separated IDs, at most 2000 characters in total
- results are paged with `limit` (default 100, max 10,000), so `limit` is always set
- `epss` and `percentile` are returned as decimal strings; unknown CVEs are omitted
- public endpoints allow 1000 requests/minute and answer 429 beyond that
"""

import csv
import gzip
import logging
import time
from collections.abc import Collection, Iterable, Mapping
from pathlib import Path

import httpx
from pydantic import ValidationError

from vulnrank.adapters._raw import RawModel, describe
from vulnrank.adapters.enrichment._http import Sleep, get_json
from vulnrank.adapters.enrichment.cache import JsonCache
from vulnrank.domain.models import EpssScore
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
MAX_CVE_PARAM_LENGTH = 2000


class _Row(RawModel):
    cve: str
    epss: float
    percentile: float


class _Response(RawModel):
    data: list[object]


def batch_by_length(
    cve_ids: Iterable[str], max_length: int = MAX_CVE_PARAM_LENGTH
) -> list[list[str]]:
    """Split IDs so each comma-joined batch fits within `max_length` characters."""
    batches: list[list[str]] = []
    current: list[str] = []
    length = 0
    for cve in cve_ids:
        if current and length + 1 + len(cve) > max_length:
            batches.append(current)
            current, length = [], 0
        length += len(cve) + (1 if current else 0)
        current.append(cve)
    if current:
        batches.append(current)
    return batches


def parse_rows(rows: Iterable[object], where: str) -> dict[str, EpssScore]:
    scores: dict[str, EpssScore] = {}
    for index, raw in enumerate(rows):
        try:
            row = _Row.model_validate(raw)
            scores[row.cve.upper()] = EpssScore(score=row.epss, percentile=row.percentile)
        except ValidationError as exc:
            logger.warning("skipping malformed EPSS row %s[%d]: %s", where, index, describe(exc))
    return scores


class EpssApiClient:
    """Implements ExploitProbability against the FIRST API, with an optional cache.

    Offline, only the cache is used (whatever its age). Online, fresh cache entries are
    reused and the rest fetched; if a request fails, stale entries are used as a fallback.
    """

    def __init__(
        self,
        http: httpx.Client,
        *,
        cache: JsonCache | None = None,
        offline: bool = False,
        url: str = EPSS_API_URL,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline
        self._url = url
        self._sleep = sleep

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        cached, missing = self._from_cache(sorted(set(cve_ids)))
        if not missing:
            return cached
        if self._offline:
            logger.warning("offline: no cached EPSS score for %d CVE(s)", len(missing))
            return cached
        return {**cached, **self._fetch_all(missing)}

    def _from_cache(self, cve_ids: list[str]) -> tuple[dict[str, EpssScore], list[str]]:
        """Split into usable cached scores and CVEs that still need a lookup."""
        if self._cache is None:
            return {}, cve_ids
        found: dict[str, EpssScore] = {}
        missing: list[str] = []
        for cve in cve_ids:
            entry = self._cache.get(cve)
            if entry is None or not (self._offline or self._cache.is_fresh(entry)):
                missing.append(cve)
            elif entry.value is None:
                continue  # looked up before: FIRST has no score for this CVE
            elif (score := _decode(entry.value)) is not None:
                found[cve] = score
            else:
                missing.append(cve)  # corrupt entry: look it up again
        return found, missing

    def _fetch_all(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        found: dict[str, EpssScore] = {}
        for batch in batch_by_length(cve_ids):
            found.update(self._fetch_batch(batch))
        return found

    def _fetch_batch(self, batch: list[str]) -> dict[str, EpssScore]:
        try:
            scores = self._request(batch)
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("EPSS lookup failed for %d CVE(s): %s", len(batch), exc)
            return self._stale(batch)
        if self._cache:
            # Cache misses too (as null) so CVEs without a score are not re-queried every run.
            self._cache.put_many({cve: _encode(scores.get(cve)) for cve in batch})
        return scores

    def _request(self, batch: list[str]) -> dict[str, EpssScore]:
        params: dict[str, str | int] = {"cve": ",".join(batch), "limit": len(batch)}
        document = get_json(self._http, self._url, params=params, sleep=self._sleep)
        response = _Response.model_validate(document)
        requested = set(batch)
        scores = parse_rows(response.data, "response.data")
        return {cve: score for cve, score in scores.items() if cve in requested}

    def _stale(self, batch: list[str]) -> dict[str, EpssScore]:
        stale: dict[str, EpssScore] = {}
        for cve in batch:
            entry = self._cache.get(cve) if self._cache else None
            if entry is not None and (score := _decode(entry.value)) is not None:
                stale[cve] = score
        if stale:
            logger.warning("using stale cached EPSS scores for %d CVE(s)", len(stale))
        return stale


def _encode(score: EpssScore | None) -> object:
    return score.model_dump() if score else None


def _decode(value: object) -> EpssScore | None:
    if value is None:
        return None
    try:
        return EpssScore.model_validate(value)
    except ValidationError:
        return None


class EpssCsvFile:
    """Implements ExploitProbability from FIRST's daily export (`epss_scores-YYYY-MM-DD.csv.gz`)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._scores: dict[str, EpssScore] | None = None

    def scores(self, cve_ids: Collection[str]) -> Mapping[str, EpssScore]:
        all_scores = self._load()
        return {cve: all_scores[cve] for cve in cve_ids if cve in all_scores}

    def _load(self) -> dict[str, EpssScore]:
        if self._scores is None:
            lines = (line for line in self._read_text().splitlines() if not line.startswith("#"))
            self._scores = parse_rows(csv.DictReader(lines), str(self._path))
        return self._scores

    def _read_text(self) -> str:
        try:
            raw = self._path.read_bytes()
            if self._path.suffix == ".gz":
                raw = gzip.decompress(raw)
            return raw.decode("utf-8")
        except (OSError, EOFError, UnicodeDecodeError) as exc:
            raise SourceError(f"cannot read EPSS file {self._path}: {exc}") from exc
